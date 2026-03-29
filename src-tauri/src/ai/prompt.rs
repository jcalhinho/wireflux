use crate::packet::PacketRecord;

pub fn build_prompt(packet: &PacketRecord) -> String {
    let src_port = packet
        .source_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_port = packet
        .destination_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let ttl = packet
        .ttl_or_hop_limit
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let flags = packet.tcp_flags.clone().unwrap_or_else(|| "-".to_string());

    format!(
        "Réponds UNIQUEMENT avec l'explication finale en français.\nInterdit: afficher ton raisonnement, \"Thinking Process\", étapes internes, checklist, analyse méta.\nFormat attendu: 3 puces maximum, simples et concrètes.\n\nTimestamp: {}\nSource: {}:{}\nDestination: {}:{}\nL3: {}\nProtocol: {}\nTTL/Hop: {}\nTCP Flags: {}\nEtherType: {}\nLength: {} bytes\nInfo: {}\nHex preview: {}",
        packet.timestamp,
        packet.source,
        src_port,
        packet.destination,
        dst_port,
        packet.ip_version,
        packet.protocol,
        ttl,
        flags,
        packet.ethertype,
        packet.length,
        packet.info,
        packet.raw_hex,
    )
}

pub fn build_compact_prompt(packet: &PacketRecord) -> String {
    let src_port = packet
        .source_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_port = packet
        .destination_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());

    format!(
        "Réponds en français avec l'explication finale uniquement.\nInterdit: Thinking Process / raisonnement.\nEn 2-3 phrases max.\nSource: {}:{}\nDestination: {}:{}\nL3/Proto: {}/{}\nTaille: {} bytes\nInfo: {}",
        packet.source,
        src_port,
        packet.destination,
        dst_port,
        packet.ip_version,
        packet.protocol,
        packet.length,
        packet.info
    )
}

pub fn local_explanation(packet: &PacketRecord) -> String {
    let src_port = packet
        .source_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let dst_port = packet
        .destination_port
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let ttl = packet
        .ttl_or_hop_limit
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let flags = packet.tcp_flags.clone().unwrap_or_else(|| "-".to_string());

    format!(
        "Type: {} / {}\nTrajet: {}:{} -> {}:{}\nTaille: {} octets\nTTL/Hop: {}\nFlags TCP: {}\nEtherType: {}\nRésumé: {}",
        packet.ip_version,
        packet.protocol,
        packet.source,
        src_port,
        packet.destination,
        dst_port,
        packet.length,
        ttl,
        flags,
        packet.ethertype,
        packet.info,
    )
}
