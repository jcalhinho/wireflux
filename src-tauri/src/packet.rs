use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRecord {
    pub id: u64,
    pub timestamp: String,
    pub source: String,
    pub source_port: Option<u16>,
    pub destination: String,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub ip_version: String,
    pub ttl_or_hop_limit: Option<u8>,
    pub tcp_flags: Option<String>,
    pub ethertype: String,
    pub length: u32,
    pub info: String,
    pub raw_hex: String,
}

#[derive(Debug)]
struct ParsedPacketFields {
    source: String,
    source_port: Option<u16>,
    destination: String,
    destination_port: Option<u16>,
    protocol: String,
    ip_version: String,
    ttl_or_hop_limit: Option<u8>,
    tcp_flags: Option<String>,
    ethertype: String,
    info: String,
}

impl ParsedPacketFields {
    fn unknown(reason: &str) -> Self {
        Self {
            source: "unknown".to_string(),
            source_port: None,
            destination: "unknown".to_string(),
            destination_port: None,
            protocol: "OTHER".to_string(),
            ip_version: "L2".to_string(),
            ttl_or_hop_limit: None,
            tcp_flags: None,
            ethertype: "0x0000".to_string(),
            info: reason.to_string(),
        }
    }
}

#[derive(Debug)]
struct TransportOutcome {
    source_port: Option<u16>,
    destination_port: Option<u16>,
    protocol: String,
    tcp_flags: Option<String>,
}

pub fn decode_packet(
    id: u64,
    ts_sec: u32,
    ts_fraction: u32,
    ts_is_nano: bool,
    captured_len: u32,
    payload: &[u8],
) -> PacketRecord {
    let timestamp = format_timestamp(ts_sec, ts_fraction, ts_is_nano);
    let raw_hex = hex_preview(payload, 96);
    let parsed = parse_network_fields(payload);

    PacketRecord {
        id,
        timestamp,
        source: parsed.source,
        source_port: parsed.source_port,
        destination: parsed.destination,
        destination_port: parsed.destination_port,
        protocol: parsed.protocol,
        ip_version: parsed.ip_version,
        ttl_or_hop_limit: parsed.ttl_or_hop_limit,
        tcp_flags: parsed.tcp_flags,
        ethertype: parsed.ethertype,
        length: captured_len,
        info: parsed.info,
        raw_hex,
    }
}

fn format_timestamp(ts_sec: u32, ts_fraction: u32, ts_is_nano: bool) -> String {
    if ts_is_nano {
        let micros = ts_fraction / 1_000;
        format!("{ts_sec}.{:06}", micros)
    } else {
        format!("{ts_sec}.{:06}", ts_fraction)
    }
}

fn parse_network_fields(payload: &[u8]) -> ParsedPacketFields {
    if payload.len() < 14 {
        return ParsedPacketFields::unknown("Truncated Ethernet frame");
    }

    let ethertype = u16::from_be_bytes([payload[12], payload[13]]);
    let ethertype_text = format!("0x{ethertype:04X}");

    match ethertype {
        0x0800 => parse_ipv4(payload, ethertype_text),
        0x86DD => parse_ipv6(payload, ethertype_text),
        0x0806 => ParsedPacketFields {
            source: format_mac(&payload[6..12]),
            source_port: None,
            destination: format_mac(&payload[0..6]),
            destination_port: None,
            protocol: "ARP".to_string(),
            ip_version: "ARP".to_string(),
            ttl_or_hop_limit: None,
            tcp_flags: None,
            ethertype: ethertype_text,
            info: "Address Resolution Protocol".to_string(),
        },
        _ => ParsedPacketFields {
            source: format_mac(&payload[6..12]),
            source_port: None,
            destination: format_mac(&payload[0..6]),
            destination_port: None,
            protocol: format!("ETH_{ethertype:04X}"),
            ip_version: "L2".to_string(),
            ttl_or_hop_limit: None,
            tcp_flags: None,
            ethertype: ethertype_text.clone(),
            info: format!("EtherType {ethertype_text}"),
        },
    }
}

fn parse_ipv4(payload: &[u8], ethertype: String) -> ParsedPacketFields {
    if payload.len() < 34 {
        return ParsedPacketFields {
            ethertype,
            info: "Truncated IPv4 packet".to_string(),
            ip_version: "IPv4".to_string(),
            protocol: "IPv4".to_string(),
            ..ParsedPacketFields::unknown("Truncated IPv4 packet")
        };
    }

    let ip_start = 14usize;
    let ihl = ((payload[ip_start] & 0x0f) as usize) * 4;
    if ihl < 20 || payload.len() < ip_start + ihl {
        return ParsedPacketFields {
            ethertype,
            info: "Invalid IPv4 header".to_string(),
            ip_version: "IPv4".to_string(),
            protocol: "IPv4".to_string(),
            ..ParsedPacketFields::unknown("Invalid IPv4 header")
        };
    }

    let ttl = payload[ip_start + 8];
    let proto_id = payload[ip_start + 9];
    let source = format_ipv4(&payload[ip_start + 12..ip_start + 16]);
    let destination = format_ipv4(&payload[ip_start + 16..ip_start + 20]);

    let transport_start = ip_start + ihl;
    let transport = parse_transport(proto_id, payload, transport_start, "IPv4");
    let info = build_info(
        &source,
        &destination,
        transport.source_port,
        transport.destination_port,
        transport.tcp_flags.as_deref(),
    );

    ParsedPacketFields {
        source,
        source_port: transport.source_port,
        destination,
        destination_port: transport.destination_port,
        protocol: transport.protocol,
        ip_version: "IPv4".to_string(),
        ttl_or_hop_limit: Some(ttl),
        tcp_flags: transport.tcp_flags,
        ethertype,
        info,
    }
}

fn parse_ipv6(payload: &[u8], ethertype: String) -> ParsedPacketFields {
    if payload.len() < 54 {
        return ParsedPacketFields {
            ethertype,
            info: "Truncated IPv6 packet".to_string(),
            ip_version: "IPv6".to_string(),
            protocol: "IPv6".to_string(),
            ..ParsedPacketFields::unknown("Truncated IPv6 packet")
        };
    }

    let ip_start = 14usize;
    let next_header = payload[ip_start + 6];
    let hop_limit = payload[ip_start + 7];
    let source = format_ipv6(&payload[ip_start + 8..ip_start + 24]);
    let destination = format_ipv6(&payload[ip_start + 24..ip_start + 40]);

    let transport_start = ip_start + 40;
    let transport = parse_transport(next_header, payload, transport_start, "IPv6");
    let info = build_info(
        &source,
        &destination,
        transport.source_port,
        transport.destination_port,
        transport.tcp_flags.as_deref(),
    );

    ParsedPacketFields {
        source,
        source_port: transport.source_port,
        destination,
        destination_port: transport.destination_port,
        protocol: transport.protocol,
        ip_version: "IPv6".to_string(),
        ttl_or_hop_limit: Some(hop_limit),
        tcp_flags: transport.tcp_flags,
        ethertype,
        info,
    }
}

fn parse_transport(
    proto_id: u8,
    payload: &[u8],
    offset: usize,
    ip_version: &str,
) -> TransportOutcome {
    match proto_id {
        6 => {
            if payload.len() < offset + 20 {
                return TransportOutcome {
                    source_port: None,
                    destination_port: None,
                    protocol: "TCP".to_string(),
                    tcp_flags: None,
                };
            }

            let source_port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let destination_port = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let flags = payload[offset + 13];

            TransportOutcome {
                source_port: Some(source_port),
                destination_port: Some(destination_port),
                protocol: "TCP".to_string(),
                tcp_flags: Some(format_tcp_flags(flags)),
            }
        }
        17 => {
            if payload.len() < offset + 8 {
                return TransportOutcome {
                    source_port: None,
                    destination_port: None,
                    protocol: "UDP".to_string(),
                    tcp_flags: None,
                };
            }

            let source_port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let destination_port = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);

            TransportOutcome {
                source_port: Some(source_port),
                destination_port: Some(destination_port),
                protocol: "UDP".to_string(),
                tcp_flags: None,
            }
        }
        1 if ip_version == "IPv4" => TransportOutcome {
            source_port: None,
            destination_port: None,
            protocol: "ICMP".to_string(),
            tcp_flags: None,
        },
        58 if ip_version == "IPv6" => TransportOutcome {
            source_port: None,
            destination_port: None,
            protocol: "ICMPv6".to_string(),
            tcp_flags: None,
        },
        _ => TransportOutcome {
            source_port: None,
            destination_port: None,
            protocol: ip_version.to_string(),
            tcp_flags: None,
        },
    }
}

fn format_tcp_flags(flags: u8) -> String {
    let mut names = Vec::new();
    if flags & 0x01 != 0 {
        names.push("FIN");
    }
    if flags & 0x02 != 0 {
        names.push("SYN");
    }
    if flags & 0x04 != 0 {
        names.push("RST");
    }
    if flags & 0x08 != 0 {
        names.push("PSH");
    }
    if flags & 0x10 != 0 {
        names.push("ACK");
    }
    if flags & 0x20 != 0 {
        names.push("URG");
    }
    if flags & 0x40 != 0 {
        names.push("ECE");
    }
    if flags & 0x80 != 0 {
        names.push("CWR");
    }

    if names.is_empty() {
        "NONE".to_string()
    } else {
        names.join(",")
    }
}

fn build_info(
    source: &str,
    destination: &str,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    tcp_flags: Option<&str>,
) -> String {
    let mut base = match (source_port, destination_port) {
        (Some(src), Some(dst)) => format!("{source}:{src} -> {destination}:{dst}"),
        _ => format!("{source} -> {destination}"),
    };

    if let Some(flags) = tcp_flags {
        base.push_str(&format!(" [{flags}]"));
    }

    base
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_ipv4(bytes: &[u8]) -> String {
    if bytes.len() != 4 {
        return "unknown".to_string();
    }
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn format_ipv6(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return "unknown".to_string();
    }

    let mut chunks = Vec::with_capacity(8);
    for i in 0..8 {
        let hi = bytes[i * 2] as u16;
        let lo = bytes[i * 2 + 1] as u16;
        chunks.push(format!("{:x}", (hi << 8) | lo));
    }
    chunks.join(":")
}

fn hex_preview(payload: &[u8], max_bytes: usize) -> String {
    let preview_len = payload.len().min(max_bytes);
    payload[..preview_len]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
