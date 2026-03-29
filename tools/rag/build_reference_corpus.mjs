#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

const rootDir = process.cwd();
const outputPath = path.join(rootDir, "public/docs/rag/wireflux-reference-corpus.jsonl");
const generatedAt = new Date().toISOString();

const chunks = [];

function normalizeList(values = []) {
  return Array.from(
    new Set(
      values
        .map((value) => String(value ?? "").trim())
        .filter(Boolean)
        .map((value) => value.toLowerCase()),
    ),
  );
}

function computeHash(input) {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function addChunk({
  chunkId,
  docId,
  sourceId,
  sourceUrl,
  title,
  section,
  content,
  tags,
  osiLayers = [],
  ports = [],
  protocols = [],
  language = "en",
  confidenceLevel = "high",
  publishedAt = null,
}) {
  const cleanTags = normalizeList(tags);
  const cleanProtocols = normalizeList(protocols);
  const cleanPorts = Array.from(
    new Set(
      ports
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value >= 0 && value <= 65535),
    ),
  );
  const cleanOsi = Array.from(
    new Set(
      osiLayers
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value >= 1 && value <= 7),
    ),
  );

  const row = {
    chunk_id: chunkId,
    doc_id: docId,
    source_id: sourceId,
    source_url: sourceUrl,
    title,
    section: section || "",
    language,
    content: String(content || "").trim(),
    tags: cleanTags.length > 0 ? cleanTags : ["network"],
    osi_layers: cleanOsi,
    ports: cleanPorts,
    protocols: cleanProtocols,
    retrieved_at: generatedAt,
    confidence_level: confidenceLevel,
    license: "refer-to-source",
  };

  if (publishedAt) {
    row.published_at = publishedAt;
  }

  row.hash_sha256 = computeHash(
    [
      row.chunk_id,
      row.doc_id,
      row.source_id,
      row.source_url,
      row.title,
      row.section,
      row.language,
      row.content,
      row.tags.join(","),
      row.osi_layers.join(","),
      row.ports.join(","),
      row.protocols.join(","),
    ].join("|"),
  );

  chunks.push(row);
}

const protocolReferences = [
  {
    chunkId: "rfc9293-tcp-core",
    docId: "rfc9293",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9293",
    title: "Transmission Control Protocol (TCP)",
    section: "Connection establishment and reliability",
    content:
      "TCP is a connection-oriented transport protocol. It uses sequence numbers, acknowledgments, retransmission, and flow control to provide reliable ordered delivery between endpoints.",
    tags: ["tcp", "transport", "reliability", "handshake"],
    osiLayers: [4],
    protocols: ["tcp"],
  },
  {
    chunkId: "rfc768-udp-core",
    docId: "rfc768",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc768",
    title: "User Datagram Protocol (UDP)",
    section: "Header format",
    content:
      "UDP provides source port, destination port, length, and checksum fields. It is connectionless and does not provide retransmission or in-order delivery.",
    tags: ["udp", "transport", "datagram"],
    osiLayers: [4],
    protocols: ["udp"],
  },
  {
    chunkId: "rfc791-ipv4-core",
    docId: "rfc791",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc791",
    title: "Internet Protocol Version 4",
    section: "Header and TTL",
    content:
      "IPv4 carries packets across routed networks. Routers decrement TTL by at least one per hop; a packet is discarded when TTL reaches zero.",
    tags: ["ipv4", "ttl", "routing", "ip"],
    osiLayers: [3],
    protocols: ["ipv4"],
  },
  {
    chunkId: "rfc8200-ipv6-core",
    docId: "rfc8200",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc8200",
    title: "Internet Protocol Version 6",
    section: "Base header",
    content:
      "IPv6 uses a fixed-size base header and Hop Limit instead of TTL. Extension headers may be chained after the base header before transport data.",
    tags: ["ipv6", "hop-limit", "extension-headers", "ip"],
    osiLayers: [3],
    protocols: ["ipv6"],
  },
  {
    chunkId: "rfc826-arp-core",
    docId: "rfc826",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc826",
    title: "Address Resolution Protocol (ARP)",
    section: "Address mapping",
    content:
      "ARP maps IPv4 addresses to link-layer addresses on local networks. ARP traffic is commonly seen as broadcast requests and unicast replies.",
    tags: ["arp", "l2", "address-resolution", "ethernet"],
    osiLayers: [2, 3],
    protocols: ["arp", "ipv4"],
  },
  {
    chunkId: "rfc792-icmpv4-core",
    docId: "rfc792",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc792",
    title: "Internet Control Message Protocol (ICMP)",
    section: "Control and error messages",
    content:
      "ICMP provides diagnostics and control information for IPv4, including echo request/reply and error reporting such as destination unreachable and time exceeded.",
    tags: ["icmp", "diagnostic", "control", "ipv4"],
    osiLayers: [3],
    protocols: ["icmp", "ipv4"],
  },
  {
    chunkId: "rfc4443-icmpv6-core",
    docId: "rfc4443",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc4443",
    title: "ICMPv6",
    section: "Error and informational messages",
    content:
      "ICMPv6 is required for IPv6 operation and supports error signaling and diagnostics. Neighbor discovery relies on ICMPv6 message types.",
    tags: ["icmpv6", "ipv6", "neighbor-discovery", "diagnostic"],
    osiLayers: [3],
    protocols: ["icmpv6", "ipv6"],
  },
  {
    chunkId: "rfc1034-dns-concepts",
    docId: "rfc1034",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc1034",
    title: "Domain Names - Concepts and Facilities",
    section: "Resolver and authoritative roles",
    content:
      "DNS separates recursive resolution and authoritative answers. Caching and delegation are central mechanisms for scalable name resolution.",
    tags: ["dns", "resolution", "cache", "delegation"],
    osiLayers: [7],
    ports: [53],
    protocols: ["udp", "tcp", "dns"],
  },
  {
    chunkId: "rfc1035-dns-message-format",
    docId: "rfc1035",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc1035",
    title: "Domain Names - Implementation and Specification",
    section: "Message header and resource records",
    content:
      "DNS messages include header flags, question section, and resource-record sections. UDP is common; TCP is used for large responses and specific operations.",
    tags: ["dns", "resource-records", "udp", "tcp"],
    osiLayers: [7],
    ports: [53],
    protocols: ["udp", "tcp", "dns"],
  },
  {
    chunkId: "rfc8446-tls13-core",
    docId: "rfc8446",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc8446",
    title: "Transport Layer Security 1.3",
    section: "Handshake and encrypted records",
    content:
      "TLS 1.3 encrypts most handshake messages after initial key exchange and uses authenticated encryption for application data confidentiality and integrity.",
    tags: ["tls", "encryption", "handshake", "https"],
    osiLayers: [6, 7],
    ports: [443],
    protocols: ["tcp", "tls"],
  },
  {
    chunkId: "rfc7858-dot",
    docId: "rfc7858",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc7858",
    title: "Specification for DNS over TLS",
    section: "Privacy profile",
    content:
      "DNS over TLS encapsulates DNS queries in TLS sessions to protect resolver privacy and integrity against passive observation.",
    tags: ["dns", "dot", "tls", "privacy"],
    osiLayers: [6, 7],
    ports: [853],
    protocols: ["tcp", "tls", "dns"],
  },
  {
    chunkId: "rfc8484-doh",
    docId: "rfc8484",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc8484",
    title: "DNS Queries over HTTPS (DoH)",
    section: "HTTP mapping",
    content:
      "DoH transports DNS messages over HTTPS, commonly using TCP or QUIC underneath, making DNS traffic blend with web traffic patterns.",
    tags: ["dns", "doh", "https", "quic"],
    osiLayers: [6, 7],
    ports: [443],
    protocols: ["tcp", "udp", "dns", "http"],
  },
  {
    chunkId: "rfc9000-quic-core",
    docId: "rfc9000",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9000",
    title: "QUIC: A UDP-Based Multiplexed and Secure Transport",
    section: "Transport properties",
    content:
      "QUIC runs over UDP, integrates transport and cryptographic handshake, and supports stream multiplexing with connection migration capabilities.",
    tags: ["quic", "udp", "transport", "multiplexing"],
    osiLayers: [4, 5, 6],
    ports: [443],
    protocols: ["udp", "quic"],
  },
  {
    chunkId: "rfc9001-quic-tls",
    docId: "rfc9001",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9001",
    title: "Using TLS to Secure QUIC",
    section: "Handshake integration",
    content:
      "QUIC uses TLS 1.3 handshake semantics but carries them in QUIC frames, not in traditional TLS-over-TCP records.",
    tags: ["quic", "tls13", "handshake", "udp443"],
    osiLayers: [5, 6],
    ports: [443],
    protocols: ["udp", "quic", "tls"],
  },
  {
    chunkId: "rfc9114-http3",
    docId: "rfc9114",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9114",
    title: "HTTP/3",
    section: "HTTP semantics over QUIC",
    content:
      "HTTP/3 maps HTTP semantics to QUIC streams. Traffic often appears as encrypted UDP flows on port 443 with QUIC transport behavior.",
    tags: ["http3", "quic", "udp443", "web"],
    osiLayers: [7],
    ports: [443],
    protocols: ["udp", "quic", "http"],
  },
  {
    chunkId: "rfc9112-http11",
    docId: "rfc9112",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9112",
    title: "HTTP/1.1",
    section: "Message syntax and routing",
    content:
      "HTTP/1.1 defines textual request and response framing. In encrypted deployments, HTTP semantics are wrapped in TLS sessions.",
    tags: ["http1.1", "web", "request", "response"],
    osiLayers: [7],
    ports: [80, 443],
    protocols: ["tcp", "http"],
  },
  {
    chunkId: "rfc9110-http-semantics",
    docId: "rfc9110",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc9110",
    title: "HTTP Semantics",
    section: "Methods and status codes",
    content:
      "HTTP semantics define method behavior, status code classes, and metadata fields independent of HTTP version framing details.",
    tags: ["http", "methods", "status-codes", "semantics"],
    osiLayers: [7],
    ports: [80, 443],
    protocols: ["tcp", "http"],
  },
  {
    chunkId: "rfc6298-rto",
    docId: "rfc6298",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc6298",
    title: "Computing TCP Retransmission Timer",
    section: "RTO estimation",
    content:
      "TCP retransmission timeout is computed from smoothed RTT and RTT variation. Excessive retransmissions indicate potential loss, congestion, or path instability.",
    tags: ["tcp", "retransmission", "rtt", "diagnostic"],
    osiLayers: [4],
    protocols: ["tcp"],
  },
  {
    chunkId: "rfc1812-router-ttl",
    docId: "rfc1812",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc1812",
    title: "Requirements for IP Version 4 Routers",
    section: "TTL processing",
    content:
      "IPv4 routers decrement TTL and discard expired packets, typically generating ICMP Time Exceeded messages under normal control-plane behavior.",
    tags: ["ipv4", "ttl", "router", "icmp"],
    osiLayers: [3],
    protocols: ["ipv4", "icmp"],
  },
  {
    chunkId: "rfc2131-dhcpv4",
    docId: "rfc2131",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc2131",
    title: "Dynamic Host Configuration Protocol",
    section: "Address lease workflow",
    content:
      "DHCPv4 typically uses UDP ports 67 and 68 for discover, offer, request, and acknowledgment exchange during host configuration.",
    tags: ["dhcp", "udp", "addressing", "bootstrapping"],
    osiLayers: [7],
    ports: [67, 68],
    protocols: ["udp", "dhcp"],
  },
  {
    chunkId: "rfc8415-dhcpv6",
    docId: "rfc8415",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc8415",
    title: "DHCP for IPv6",
    section: "Client and server messaging",
    content:
      "DHCPv6 uses UDP ports 546 (client) and 547 (server) for stateful configuration and lease management in IPv6 networks.",
    tags: ["dhcpv6", "udp", "ipv6", "addressing"],
    osiLayers: [7],
    ports: [546, 547],
    protocols: ["udp", "dhcp", "ipv6"],
  },
  {
    chunkId: "rfc6762-mdns",
    docId: "rfc6762",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc6762",
    title: "Multicast DNS",
    section: "Local name resolution",
    content:
      "mDNS performs local-link DNS resolution over multicast UDP 5353, commonly used by service discovery stacks in residential networks.",
    tags: ["mdns", "multicast", "discovery", "lan"],
    osiLayers: [7],
    ports: [5353],
    protocols: ["udp", "dns"],
  },
  {
    chunkId: "rfc4253-ssh-transport",
    docId: "rfc4253",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc4253",
    title: "SSH Transport Layer Protocol",
    section: "Key exchange and secure channel",
    content:
      "SSH establishes an encrypted and integrity-protected transport channel, typically over TCP port 22, with host key verification and rekey support.",
    tags: ["ssh", "encryption", "administration", "remote-access"],
    osiLayers: [6, 7],
    ports: [22],
    protocols: ["tcp", "ssh"],
  },
  {
    chunkId: "rfc5321-smtp",
    docId: "rfc5321",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc5321",
    title: "Simple Mail Transfer Protocol",
    section: "Mail relay semantics",
    content:
      "SMTP defines message relay and transfer commands across mail servers. Submission and relay flows often involve ports 25, 465, or 587.",
    tags: ["smtp", "mail", "submission", "relay"],
    osiLayers: [7],
    ports: [25, 465, 587],
    protocols: ["tcp", "smtp"],
  },
  {
    chunkId: "rfc5905-ntp",
    docId: "rfc5905",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc5905",
    title: "Network Time Protocol Version 4",
    section: "Time synchronization",
    content:
      "NTP synchronizes clocks over UDP port 123. Regular short periodic exchanges are normal for time discipline.",
    tags: ["ntp", "time-sync", "udp", "periodic"],
    osiLayers: [7],
    ports: [123],
    protocols: ["udp", "ntp"],
  },
  {
    chunkId: "rfc7348-vxlan",
    docId: "rfc7348",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc7348",
    title: "Virtual eXtensible Local Area Network (VXLAN)",
    section: "Overlay encapsulation",
    content:
      "VXLAN encapsulates Layer 2 frames in UDP for Layer 3 overlays, usually on UDP port 4789 in virtualized environments.",
    tags: ["vxlan", "overlay", "virtualization", "encapsulation"],
    osiLayers: [2, 3, 4],
    ports: [4789],
    protocols: ["udp", "vxlan"],
  },
  {
    chunkId: "rfc4301-ipsec-architecture",
    docId: "rfc4301",
    sourceUrl: "https://www.rfc-editor.org/rfc/rfc4301",
    title: "Security Architecture for IP",
    section: "ESP and AH usage",
    content:
      "IPsec uses ESP and AH for packet protection at the IP layer. Encrypted tunnels can hide upper-layer protocol details from passive observation.",
    tags: ["ipsec", "esp", "ah", "encryption"],
    osiLayers: [3],
    protocols: ["esp", "ah", "ipsec"],
  },
];

for (const row of protocolReferences) {
  addChunk({
    ...row,
    sourceId: "rfc-editor",
  });
}

const ianaPorts = [
  [20, "ftp-data", "tcp"], [21, "ftp", "tcp"], [22, "ssh", "tcp"], [23, "telnet", "tcp"],
  [25, "smtp", "tcp"], [53, "domain", "tcp/udp"], [67, "bootps", "udp"], [68, "bootpc", "udp"],
  [69, "tftp", "udp"], [80, "http", "tcp"], [88, "kerberos", "tcp/udp"], [110, "pop3", "tcp"],
  [111, "rpcbind", "tcp/udp"], [119, "nntp", "tcp"], [123, "ntp", "udp"], [135, "msrpc", "tcp"],
  [137, "netbios-ns", "udp"], [138, "netbios-dgm", "udp"], [139, "netbios-ssn", "tcp"],
  [143, "imap", "tcp"], [161, "snmp", "udp"], [162, "snmptrap", "udp"], [179, "bgp", "tcp"],
  [389, "ldap", "tcp/udp"], [443, "https", "tcp/udp"], [445, "microsoft-ds", "tcp"],
  [465, "submissions", "tcp"], [500, "isakmp", "udp"], [514, "syslog", "udp"], [515, "printer", "tcp"],
  [520, "rip", "udp"], [546, "dhcpv6-client", "udp"], [547, "dhcpv6-server", "udp"],
  [554, "rtsp", "tcp/udp"], [587, "submission", "tcp"], [631, "ipp", "tcp"], [636, "ldaps", "tcp"],
  [853, "domain-s", "tcp"], [989, "ftps-data", "tcp"], [990, "ftps", "tcp"], [993, "imaps", "tcp"],
  [995, "pop3s", "tcp"], [1080, "socks", "tcp"], [1194, "openvpn", "udp/tcp"], [1433, "ms-sql-s", "tcp"],
  [1434, "ms-sql-m", "udp"], [1521, "oracle", "tcp"], [1701, "l2tp", "udp"], [1723, "pptp", "tcp"],
  [1812, "radius", "udp"], [1813, "radius-acct", "udp"], [1883, "mqtt", "tcp"], [2049, "nfs", "tcp/udp"],
  [2375, "docker", "tcp"], [2376, "docker-ssl", "tcp"], [3128, "squid-http", "tcp"], [3306, "mysql", "tcp"],
  [3389, "ms-wbt-server", "tcp"], [3478, "stun", "udp/tcp"], [3690, "svn", "tcp"], [4369, "epmd", "tcp"],
  [4500, "ipsec-nat-t", "udp"], [5000, "upnp", "tcp/udp"], [5060, "sip", "udp/tcp"],
  [5061, "sips", "tcp"], [5222, "xmpp-client", "tcp"], [5353, "mdns", "udp"], [5432, "postgresql", "tcp"],
  [5672, "amqp", "tcp"], [5683, "coap", "udp"], [5900, "vnc", "tcp"], [5985, "wsman", "tcp"],
  [5986, "wsmans", "tcp"], [6379, "redis", "tcp"], [6443, "kubernetes-api", "tcp"],
  [6667, "irc", "tcp"], [8080, "http-alt", "tcp"], [8443, "https-alt", "tcp"], [8883, "secure-mqtt", "tcp"],
];

for (const [port, service, transport] of ianaPorts) {
  const protoTags = transport.includes("udp") && transport.includes("tcp")
    ? ["tcp", "udp"]
    : transport.includes("udp")
      ? ["udp"]
      : ["tcp"];
  addChunk({
    chunkId: `iana-port-${String(port).padStart(5, "0")}`,
    docId: "iana-service-names-port-numbers",
    sourceId: "iana-port-numbers",
    sourceUrl:
      "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml",
    title: `IANA Port ${port}`,
    section: `service ${service}`,
    content: `Port ${port} is commonly associated with '${service}' over ${transport}. Analysts should confirm with the current IANA registry and packet/session context before concluding service identity.`,
    tags: ["iana", "ports", service, ...protoTags],
    osiLayers: [4, 7],
    ports: [port],
    protocols: protoTags,
    confidenceLevel: "high",
  });
}

const ianaProtocolNumbers = [
  [1, "ICMP"], [2, "IGMP"], [6, "TCP"], [17, "UDP"], [41, "IPv6"], [47, "GRE"], [50, "ESP"],
  [51, "AH"], [58, "ICMPv6"], [89, "OSPF"], [132, "SCTP"],
];

for (const [number, name] of ianaProtocolNumbers) {
  addChunk({
    chunkId: `iana-proto-${String(number).padStart(3, "0")}`,
    docId: "iana-protocol-numbers",
    sourceId: "iana-protocol-registry",
    sourceUrl: "https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml",
    title: `IP Protocol Number ${number}`,
    section: name,
    content: `IANA protocol number ${number} corresponds to ${name}. This field is used in IP headers to indicate the next encapsulated protocol.`,
    tags: ["iana", "protocol-number", name.toLowerCase()],
    osiLayers: [3, 4],
    protocols: [name.toLowerCase()],
    confidenceLevel: "high",
  });
}

const wiresharkGuides = [
  {
    chunkId: "wireshark-display-filter-basics",
    section: "Display filters",
    content:
      "Wireshark display filters are expression-based and different from capture filters. Analysts should keep capture broad enough and refine views using display filters.",
    tags: ["wireshark", "display-filter", "analysis"],
  },
  {
    chunkId: "wireshark-tcp-flags-syn",
    section: "TCP flag inspection",
    content:
      "SYN without ACK usually marks handshake initiation. SYN+ACK usually marks handshake response. FIN and RST indicate session close or reset.",
    tags: ["wireshark", "tcp", "flags", "handshake"],
    ports: [443, 80, 22],
    protocols: ["tcp"],
  },
  {
    chunkId: "wireshark-ip-ttl-analysis",
    section: "IP hop analysis",
    content:
      "Comparing ip.ttl or ipv6.hlim across packets can reveal path changes, asymmetric routing hypotheses, or unusual decrement patterns.",
    tags: ["wireshark", "ttl", "hop-limit", "routing"],
    protocols: ["ipv4", "ipv6"],
  },
  {
    chunkId: "wireshark-follow-stream",
    section: "Conversation reconstruction",
    content:
      "Follow stream workflows help reconstruct request/response narratives. For encrypted traffic, metadata and timing remain key evidence when payload is unreadable.",
    tags: ["wireshark", "stream", "timeline", "metadata"],
  },
  {
    chunkId: "wireshark-dns-analysis",
    section: "DNS fields",
    content:
      "DNS analysis relies on transaction IDs, query names, response codes, and answer sections. Repeated failures or unusual query entropy can indicate abuse patterns.",
    tags: ["wireshark", "dns", "rcode", "analysis"],
    ports: [53, 853, 443],
    protocols: ["udp", "tcp", "dns"],
  },
  {
    chunkId: "wireshark-quic-observability",
    section: "QUIC visibility limits",
    content:
      "With QUIC over UDP/443, payload content is encrypted; investigators should focus on timing, packet sizes, endpoint behavior, and flow persistence.",
    tags: ["wireshark", "quic", "udp443", "encrypted-traffic"],
    ports: [443],
    protocols: ["udp", "quic"],
  },
  {
    chunkId: "wireshark-l2-l3-coherence",
    section: "Dissector checks",
    content:
      "A practical sanity check is verifying EtherType against decoded Layer 3 protocol. Incoherence can indicate malformed frames, parser issues, or capture corruption.",
    tags: ["wireshark", "ethertype", "sanity-check", "packet-quality"],
    protocols: ["ipv4", "ipv6", "arp"],
  },
  {
    chunkId: "wireshark-arp-patterns",
    section: "ARP behavior",
    content:
      "Normal ARP traffic is local-link scoped. Repeated unsolicited ARP replies or abrupt mapping changes may indicate spoofing risks in flat L2 segments.",
    tags: ["wireshark", "arp", "spoofing", "lan"],
    protocols: ["arp"],
  },
  {
    chunkId: "wireshark-icmp-time-exceeded",
    section: "Control messages",
    content:
      "ICMP Time Exceeded often reflects TTL expiration on routed paths. Correlating original flow and returned ICMP payload helps isolate hop-level issues.",
    tags: ["wireshark", "icmp", "troubleshooting", "routing"],
    protocols: ["icmp", "ipv4", "ipv6"],
  },
  {
    chunkId: "wireshark-expert-info",
    section: "Expert information",
    content:
      "Expert warnings should guide analyst attention but not be treated as proof. Confirmation should come from packet-level evidence and protocol semantics.",
    tags: ["wireshark", "expert-info", "false-positives", "triage"],
  },
];

for (const guide of wiresharkGuides) {
  addChunk({
    chunkId: guide.chunkId,
    docId: "wireshark-docs",
    sourceId: "wireshark-docs",
    sourceUrl: "https://www.wireshark.org/docs/",
    title: "Wireshark Operational Guidance",
    section: guide.section,
    content: guide.content,
    tags: guide.tags,
    osiLayers: [2, 3, 4, 7],
    ports: guide.ports || [],
    protocols: guide.protocols || [],
    confidenceLevel: "medium",
  });
}

const mitreTechniques = [
  ["T1046", "Network Service Discovery", "Scanning services and ports on remote systems is a common precursor to exploitation and lateral movement."],
  ["T1110", "Brute Force", "Repeated authentication attempts over management and remote access protocols can indicate credential guessing activity."],
  ["T1071", "Application Layer Protocol", "Adversaries can use common application protocols to blend command-and-control traffic with normal operations."],
  ["T1071.001", "Web Protocols", "HTTP(S)-based C2 can resemble legitimate web traffic; sequence, destinations, and timing become critical evidence."],
  ["T1071.004", "DNS", "DNS can be abused for command, control, or data transport through atypical query patterns and volumes."],
  ["T1571", "Non-Standard Port", "Use of unexpected ports for known protocols can be an evasion indicator requiring context-based validation."],
  ["T1041", "Exfiltration Over C2 Channel", "Exfiltration may occur inside established command-and-control channels to reduce detection likelihood."],
  ["T1568", "Dynamic Resolution", "Frequent endpoint resolution changes can support resilient malicious infrastructure and evasive operations."],
  ["T1498", "Network Denial of Service", "Sustained abnormal packet rates against services can indicate resource exhaustion attempts."],
  ["T1021", "Remote Services", "Remote service protocols are frequently used for persistence and lateral movement once credentials are obtained."],
  ["T1133", "External Remote Services", "Adversaries can access internet-facing remote services to gain initial foothold or maintain access."],
  ["T1090", "Proxy", "Proxy infrastructure can obscure final C2 destinations and complicate attribution."],
  ["T1001", "Data Obfuscation", "C2 payloads can be obfuscated to reduce signature-based detection effectiveness."],
  ["T1040", "Network Sniffing", "Traffic capture by adversaries can expose credentials and operational context for follow-on actions."],
  ["T1016", "System Network Configuration Discovery", "Collection of local network configuration can guide target selection and routing-aware movement."],
  ["T1595", "Active Scanning", "Pre-compromise active scanning can identify reachable assets, versions, and service surfaces."],
  ["T1573", "Encrypted Channel", "Encrypted channels protect adversary traffic content and force defenders to rely on metadata and behavior."],
];

for (const [techniqueId, techniqueName, description] of mitreTechniques) {
  addChunk({
    chunkId: `mitre-${techniqueId.toLowerCase().replace(".", "-")}`,
    docId: `mitre-${techniqueId.toLowerCase()}`,
    sourceId: "mitre-attack",
    sourceUrl: `https://attack.mitre.org/techniques/${techniqueId}/`,
    title: `${techniqueId} ${techniqueName}`,
    section: "Enterprise ATT&CK",
    content: description,
    tags: ["mitre", "attack", techniqueId.toLowerCase(), "detection"],
    osiLayers: [3, 4, 7],
    protocols: ["tcp", "udp", "dns", "http"],
    confidenceLevel: "high",
  });
}

const operationalSecurityChunks = [
  {
    chunkId: "cisa-kev-prioritization",
    docId: "cisa-kev-catalog",
    sourceId: "cisa-kev",
    sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    title: "CISA KEV Prioritization",
    section: "Operational patch urgency",
    content:
      "When a CVE is listed in CISA KEV, remediation priority is typically higher because exploitation has been observed in the wild.",
    tags: ["cisa", "kev", "prioritization", "vulnerability-management"],
  },
  {
    chunkId: "nvd-cvss-usage",
    docId: "nvd-vulnerability-database",
    sourceId: "nvd",
    sourceUrl: "https://nvd.nist.gov/",
    title: "NVD CVSS Interpretation",
    section: "Severity and vectors",
    content:
      "CVSS helps rank technical severity, but operational risk also depends on exploitability, exposure, and asset criticality.",
    tags: ["nvd", "cvss", "risk", "cve"],
  },
  {
    chunkId: "certfr-incident-triage",
    docId: "cert-fr-guidance",
    sourceId: "cert-fr",
    sourceUrl: "https://www.cert.ssi.gouv.fr/",
    title: "CERT-FR Incident Triage",
    section: "Initial investigation workflow",
    content:
      "Incident triage should quickly determine scope, affected assets, and probable entry points, then preserve evidence before remediation actions.",
    tags: ["cert-fr", "incident-response", "triage", "forensics"],
    language: "fr",
  },
  {
    chunkId: "anssi-hygiene-principles",
    docId: "anssi-guides",
    sourceId: "anssi",
    sourceUrl: "https://cyber.gouv.fr/publications",
    title: "ANSSI Hygiene Principles",
    section: "Hardening baseline",
    content:
      "Security hardening relies on patching discipline, least privilege, segmentation, and monitored administration channels.",
    tags: ["anssi", "hardening", "baseline", "defense-in-depth"],
    language: "fr",
  },
  {
    chunkId: "owasp-logging-guidance",
    docId: "owasp-cheat-sheet-logging",
    sourceId: "owasp-cheat-sheet",
    sourceUrl: "https://cheatsheetseries.owasp.org/",
    title: "OWASP Logging Guidance",
    section: "Security telemetry",
    content:
      "Security logs should be structured, timestamped, and correlated across systems to support rapid detection and post-incident analysis.",
    tags: ["owasp", "logging", "telemetry", "detection"],
    confidenceLevel: "medium",
  },
  {
    chunkId: "security-beaconing-heuristic",
    docId: "wireflux-detection-guidance",
    sourceId: "mitre-attack",
    sourceUrl: "https://attack.mitre.org/",
    title: "Beaconing Behavioral Indicator",
    section: "Periodic outbound patterns",
    content:
      "Periodic low-volume outbound traffic to a stable destination can indicate beaconing, but software updates and telemetry can produce similar periodic patterns.",
    tags: ["beaconing", "c2", "false-positive", "behavioral-detection"],
    confidenceLevel: "medium",
  },
  {
    chunkId: "security-bruteforce-heuristic",
    docId: "wireflux-detection-guidance",
    sourceId: "mitre-attack",
    sourceUrl: "https://attack.mitre.org/techniques/T1110/",
    title: "Brute Force Indicator",
    section: "Authentication failures",
    content:
      "Repeated authentication attempts over SSH, RDP, SMTP, or web login channels can indicate brute force, especially with rapid failure bursts.",
    tags: ["bruteforce", "authentication", "ssh", "rdp"],
    ports: [22, 25, 3389, 443],
    protocols: ["tcp"],
    confidenceLevel: "high",
  },
  {
    chunkId: "security-synscan-heuristic",
    docId: "wireflux-detection-guidance",
    sourceId: "mitre-attack",
    sourceUrl: "https://attack.mitre.org/techniques/T1046/",
    title: "SYN Scan Indicator",
    section: "Pre-compromise discovery",
    content:
      "A high number of SYN packets to many distinct targets or ports in a short window is consistent with service discovery scanning behavior.",
    tags: ["syn-scan", "discovery", "t1046", "recon"],
    protocols: ["tcp"],
    confidenceLevel: "high",
  },
  {
    chunkId: "security-exfil-heuristic",
    docId: "wireflux-detection-guidance",
    sourceId: "mitre-attack",
    sourceUrl: "https://attack.mitre.org/techniques/T1041/",
    title: "Exfiltration Indicator",
    section: "Outbound volume and destination context",
    content:
      "Unusual outbound volume spikes to uncommon destinations, especially outside known business patterns, can indicate exfiltration and should trigger validation.",
    tags: ["exfiltration", "outbound", "t1041", "anomaly"],
    protocols: ["tcp", "udp"],
    confidenceLevel: "medium",
  },
  {
    chunkId: "security-dns-tunnel-indicator",
    docId: "wireflux-detection-guidance",
    sourceId: "mitre-attack",
    sourceUrl: "https://attack.mitre.org/techniques/T1071/004/",
    title: "DNS Tunneling Indicator",
    section: "Query shape and entropy",
    content:
      "Long, high-entropy, repetitive subdomain queries with unusual frequency can indicate DNS-based data transfer or command signaling.",
    tags: ["dns", "tunneling", "entropy", "t1071.004"],
    ports: [53],
    protocols: ["udp", "tcp", "dns"],
    confidenceLevel: "medium",
  },
];

for (const row of operationalSecurityChunks) {
  addChunk({
    ...row,
    osiLayers: row.osiLayers || [3, 4, 7],
    ports: row.ports || [],
    protocols: row.protocols || ["tcp", "udp"],
    language: row.language || "en",
  });
}

// Deterministic sort for reproducible diffs.
chunks.sort((a, b) => String(a.chunk_id).localeCompare(String(b.chunk_id)));

const lines = chunks.map((row) => JSON.stringify(row));
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${lines.join("\n")}\n`, "utf8");

console.log(`[wireflux-rag] generated ${chunks.length} chunks -> ${outputPath}`);
