import { KNOWN_PORTS, LAYER_KEYS, state } from "./domState.js";

const APPLICATION_PORTS = new Set([
  20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 587, 993, 995, 3306, 5432, 6379, 8080, 8443,
]);
const PRESENTATION_HINT_PORTS = new Set([443, 8443, 993, 995, 636, 587, 465]);

const L2_CONTROL_ETHERTYPES = new Set([
  "0X0806", // ARP
  "0X8100", // VLAN
  "0X88A8",
  "0X88CC",
  "0X888E",
  "0X8809",
  "0X8847",
  "0X8848",
]);
const L3_ETHERTYPES = new Set(["0X0800", "0X86DD"]);
const L2_INFO_MARKERS = ["arp", "lldp", "stp", "bpdu", "eapol", "lacp", "vlan", "cdp", "mpls"];
const L3_PROTOCOLS = new Set(["IPV4", "IPV6", "ICMP", "ICMPV6", "IGMP", "ESP", "AH", "GRE", "OSPF"]);
const L3_INFO_MARKERS = [
  "icmp",
  "igmp",
  "neighbor solicitation",
  "neighbor advertisement",
  "router solicitation",
  "router advertisement",
  "ttl exceeded",
  "fragment",
  "hop limit",
];

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

export function formatOptional(value, fallback = "-") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  return String(value);
}

export function serviceNameForPort(port) {
  if (port === null || port === undefined) {
    return "port non défini";
  }
  return KNOWN_PORTS.get(port) || "service non identifié";
}

export function parseTimestampValue(timestampText) {
  const parsed = Number.parseFloat(String(timestampText || "0"));
  return Number.isFinite(parsed) ? parsed : 0;
}

export function safeToLocaleTime(timestampMs) {
  return new Date(timestampMs).toLocaleTimeString("fr-FR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function isPrivateIp(ip) {
  if (typeof ip !== "string") {
    return false;
  }
  const normalized = ip.toLowerCase();
  return (
    normalized.startsWith("10.") ||
    normalized.startsWith("192.168.") ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(normalized) ||
    normalized === "127.0.0.1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd")
  );
}

export function parseTcpFlags(flagsText) {
  if (!flagsText) {
    return new Set();
  }
  return new Set(
    String(flagsText)
      .split(",")
      .map((value) => value.trim().toUpperCase())
      .filter(Boolean),
  );
}

function layerName(value) {
  const normalized = String(value || "").toLowerCase().trim();
  return LAYER_KEYS.includes(normalized) ? normalized : null;
}

export function activeLayerKeys() {
  if (state.allLayersActive) {
    return new Set(LAYER_KEYS);
  }
  const normalized = new Set();
  for (const layer of state.activeLayers || []) {
    const safe = layerName(layer);
    if (safe) {
      normalized.add(safe);
    }
  }
  if (normalized.size === 0) {
    return new Set(LAYER_KEYS);
  }
  return normalized;
}

export function resolveOsiLayer(packet) {
  const layers = resolvePacketLayers(packet);
  return layers[0] || "l3";
}

export function resolvePacketLayers(packet) {
  const proto = protocolFamily(packet);
  if (isDataLinkPacket(packet) && proto !== "TCP" && proto !== "UDP") {
    return ["l2"];
  }

  if (proto === "TCP" || proto === "UDP") {
    const heuristics = detectLayerHeuristics(packet);
    const layers = [];
    if (isApplicationPacket(packet)) {
      layers.push("l7");
    }
    if (heuristics.presentation.matched) {
      layers.push("l6");
    }
    if (heuristics.session.matched) {
      layers.push("l5");
    }
    if (layers.length > 0) {
      layers.push("l4");
      return Array.from(new Set(layers));
    }
    return ["l4"];
  }

  if (isNetworkPacket(packet)) {
    return ["l3"];
  }

  return ["l2"];
}

function confidenceFromScore(score) {
  if (score >= 5) {
    return "élevée";
  }
  if (score >= 3) {
    return "moyenne";
  }
  if (score >= 1) {
    return "faible";
  }
  return "nulle";
}

function falsePositiveRiskForEvidence(evidenceKinds) {
  if (evidenceKinds.size === 0) {
    return "élevé";
  }
  if (evidenceKinds.size === 1 && evidenceKinds.has("port")) {
    return "élevé";
  }
  if (evidenceKinds.has("port") && !evidenceKinds.has("payload")) {
    return "moyen";
  }
  return "faible";
}

function detectPresentationLayer(packet) {
  const proto = protocolFamily(packet);
  const info = String(packet?.info || "").toLowerCase();
  const raw = String(packet?.raw_hex || "").toLowerCase().replaceAll(" ", "");
  const srcPort = packet?.source_port;
  const dstPort = packet?.destination_port;
  const evidenceKinds = new Set();
  const reasons = [];
  let score = 0;

  const hasTlsRecord = /(16030[1-4]|17030[1-4]|14030[1-4])/.test(raw);
  if (hasTlsRecord) {
    score += 3;
    evidenceKinds.add("payload");
    reasons.push("signature TLS visible dans la charge utile");
  }

  if (/tls|ssl|certificate|client hello|server hello|alpn|http\/2|http\/3|quic/.test(info)) {
    score += 2;
    evidenceKinds.add("metadata");
    reasons.push("métadonnée protocolaire compatible chiffrement/encodage");
  }

  if (PRESENTATION_HINT_PORTS.has(srcPort) || PRESENTATION_HINT_PORTS.has(dstPort)) {
    score += 1;
    evidenceKinds.add("port");
    reasons.push("port fréquemment lié à TLS/chiffrement");
  }

  if (proto === "UDP" && (srcPort === 443 || dstPort === 443) && /quic|http\/3/.test(info)) {
    score += 2;
    evidenceKinds.add("metadata");
    reasons.push("indice QUIC/HTTP3 (chiffrement applicatif)");
  }

  const matched = score >= 3;
  const confidence = confidenceFromScore(score);
  const falsePositiveRisk = falsePositiveRiskForEvidence(evidenceKinds);
  const falsePositiveNote =
    falsePositiveRisk === "élevé"
      ? "Risque élevé: corrélation surtout basée sur le port, sans preuve forte dans le payload."
      : falsePositiveRisk === "moyen"
        ? "Risque moyen: plusieurs indices existent, mais absence de signature payload explicite."
        : "Risque faible: indices multi-sources (payload + métadonnées) cohérents.";

  return {
    matched,
    confidence,
    score,
    reasons,
    falsePositiveRisk,
    falsePositiveNote,
  };
}

function detectSessionLayer(packet) {
  const proto = protocolFamily(packet);
  const info = String(packet?.info || "").toLowerCase();
  const srcPort = packet?.source_port;
  const dstPort = packet?.destination_port;
  const flags = parseTcpFlags(packet?.tcp_flags);
  const payloadLen = Number(packet?.length || 0);
  const evidenceKinds = new Set();
  const reasons = [];
  let score = 0;

  if (proto === "TCP") {
    if (flags.has("SYN") && !flags.has("ACK")) {
      score += 3;
      evidenceKinds.add("state");
      reasons.push("ouverture de session TCP (SYN)");
    } else if (flags.has("SYN") && flags.has("ACK")) {
      score += 3;
      evidenceKinds.add("state");
      reasons.push("réponse handshake TCP (SYN-ACK)");
    }

    if (flags.has("FIN") || flags.has("RST")) {
      score += 3;
      evidenceKinds.add("state");
      reasons.push("fermeture/réinitialisation de session TCP");
    }

    if (flags.has("ACK") && !flags.has("PSH") && payloadLen <= 90) {
      score += 1;
      evidenceKinds.add("state");
      reasons.push("paquet ACK court compatible keep-alive/maintenance de session");
    }
  }

  if (/session|handshake|keep-?alive|resume|renegotiation|ticket/.test(info)) {
    score += 2;
    evidenceKinds.add("metadata");
    reasons.push("métadonnée évoquant une gestion d'état de session");
  }

  if (proto === "UDP" && (srcPort === 443 || dstPort === 443) && /quic/.test(info)) {
    score += 2;
    evidenceKinds.add("metadata");
    reasons.push("QUIC implique une gestion de session au-dessus d'UDP");
  }

  const matched = score >= 3;
  const confidence = confidenceFromScore(score);
  const falsePositiveRisk = falsePositiveRiskForEvidence(evidenceKinds);
  const falsePositiveNote =
    falsePositiveRisk === "élevé"
      ? "Risque élevé: peu d'indices d'état, interprétation fragile."
      : falsePositiveRisk === "moyen"
        ? "Risque moyen: indices de session présents mais partiels."
        : "Risque faible: transitions d'état session clairement observées.";

  return {
    matched,
    confidence,
    score,
    reasons,
    falsePositiveRisk,
    falsePositiveNote,
  };
}

export function detectLayerHeuristics(packet) {
  return {
    presentation: detectPresentationLayer(packet),
    session: detectSessionLayer(packet),
  };
}

export function isDnsPacket(packet) {
  return packet.destination_port === 53 || packet.source_port === 53;
}

export function isTlsPort(packet) {
  return packet.destination_port === 443 || packet.source_port === 443;
}

export function detectTlsStage(packet) {
  const raw = String(packet.raw_hex || "")
    .toLowerCase()
    .replaceAll(" ", "");

  const looksLikeTlsRecord =
    raw.includes("160301") ||
    raw.includes("160302") ||
    raw.includes("160303") ||
    raw.includes("160304");

  if (!looksLikeTlsRecord) {
    if (isTlsPort(packet) && String(packet.protocol).toUpperCase() === "TCP" && (packet.length || 0) > 200) {
      return "record";
    }
    return null;
  }

  const clientHelloPattern = /16030[1-4][0-9a-f]{4}01/;
  const serverHelloPattern = /16030[1-4][0-9a-f]{4}02/;

  if (clientHelloPattern.test(raw)) {
    return "client_hello";
  }
  if (serverHelloPattern.test(raw)) {
    return "server_hello";
  }

  return "record";
}

export function isLikelyDataPacket(packet) {
  const proto = String(packet.protocol || "").toUpperCase();
  if (proto !== "TCP") {
    return false;
  }
  const flags = parseTcpFlags(packet.tcp_flags);
  if (flags.has("PSH") && flags.has("ACK")) {
    return true;
  }
  if ((packet.length || 0) > 900 && !flags.has("SYN") && !flags.has("RST")) {
    return true;
  }
  return false;
}

export function describeProtocol(protocol) {
  switch (String(protocol || "").toUpperCase()) {
    case "TCP":
      return "Transport fiable orienté connexion: ordre, ACK, retransmission.";
    case "UDP":
      return "Transport rapide sans connexion: utile pour DNS, VoIP, streaming.";
    case "ICMP":
      return "Contrôle/routage IPv4: diagnostic (ping), erreurs réseau.";
    case "ICMPV6":
      return "Contrôle IPv6: voisinage, erreurs, signalisation réseau.";
    case "ARP":
      return "Résolution IP -> MAC sur le LAN (couche liaison).";
    default:
      return "Protocole de transport ou couche liaison détecté.";
  }
}

function protocolFamily(packet) {
  return String(packet?.protocol || "").toUpperCase();
}

function ipFamily(packet) {
  return String(packet?.ip_version || "").toUpperCase();
}

function isApplicationPacket(packet) {
  const srcPort = packet?.source_port;
  const dstPort = packet?.destination_port;
  if (APPLICATION_PORTS.has(srcPort) || APPLICATION_PORTS.has(dstPort)) {
    return true;
  }

  const info = String(packet?.info || "").toLowerCase();
  return (
    info.includes("http") ||
    info.includes("dns") ||
    info.includes("tls") ||
    info.includes("smtp") ||
    info.includes("imap")
  );
}

function isDataLinkPacket(packet) {
  const proto = protocolFamily(packet);
  const ip = ipFamily(packet);
  const info = String(packet?.info || "").toLowerCase();
  const ethertype = String(packet?.ethertype || "").toUpperCase();

  if (proto === "ARP" || ip === "ARP") {
    return true;
  }
  if (L2_CONTROL_ETHERTYPES.has(ethertype)) {
    return true;
  }
  return L2_INFO_MARKERS.some((marker) => info.includes(marker));
}

function isNetworkPacket(packet) {
  const proto = protocolFamily(packet);
  const ip = ipFamily(packet);
  const info = String(packet?.info || "").toLowerCase();
  const ethertype = String(packet?.ethertype || "").toUpperCase();
  if (proto === "ICMP" || proto === "ICMPV6") {
    return true;
  }
  if (ip === "IPV4" || ip === "IPV6") {
    return true;
  }
  if (L3_ETHERTYPES.has(ethertype)) {
    return true;
  }
  if (L3_PROTOCOLS.has(proto)) {
    return true;
  }
  return L3_INFO_MARKERS.some((marker) => info.includes(marker));
}

export function packetMatchesLayer(packet, layer) {
  const selectedLayer = String(layer || "application").toLowerCase();
  const proto = protocolFamily(packet);
  const heuristics = detectLayerHeuristics(packet);

  switch (selectedLayer) {
    case "application":
      return isApplicationPacket(packet);
    case "presentation":
      return heuristics.presentation.matched;
    case "session":
      return heuristics.session.matched;
    case "transport":
      return proto === "TCP" || proto === "UDP";
    case "network":
      return isNetworkPacket(packet);
    case "datalink":
      return isDataLinkPacket(packet);
    case "physical":
      return isDataLinkPacket(packet);
    default:
      return true;
  }
}

export function packetMatchesActiveLayers(packet) {
  if (state.allLayersActive) {
    return true;
  }
  const layers = activeLayerKeys();
  for (const layer of layers) {
    if (packetMatchesLayer(packet, layer)) {
      return true;
    }
  }
  return false;
}

export function getLayerFilteredPackets() {
  if (state.allLayersActive) {
    return state.packets;
  }
  return state.packets.filter((packet) => packetMatchesActiveLayers(packet));
}

export function describeIpLayer(ipVersion) {
  switch (String(ipVersion || "").toUpperCase()) {
    case "IPV4":
      return "Adressage 32 bits, encore majoritaire sur Internet.";
    case "IPV6":
      return "Adressage 128 bits, conçu pour l'extension d'Internet.";
    case "ARP":
      return "Découverte d'adresse MAC à partir de l'IP locale.";
    default:
      return "Couche réseau/liaison détectée.";
  }
}

export function describeTcpFlags(flagsText) {
  const flags = parseTcpFlags(flagsText);
  if (flags.size === 0) {
    return "Aucun flag TCP notable";
  }

  const details = [];
  if (flags.has("SYN")) {
    details.push("SYN: ouverture de connexion");
  }
  if (flags.has("ACK")) {
    details.push("ACK: accusé de réception");
  }
  if (flags.has("PSH")) {
    details.push("PSH: livraison immédiate appli");
  }
  if (flags.has("RST")) {
    details.push("RST: reset de connexion");
  }
  if (flags.has("FIN")) {
    details.push("FIN: fermeture propre");
  }

  return details.join(" | ");
}

export function listItemsToHtml(items) {
  return items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

export function parseAiResponse(rawText) {
  const text = String(rawText || "").trim();
  if (!text) {
    return {
      source: "vide",
      body: "",
      diagnostics: [],
    };
  }

  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object") {
      const source = String(parsed.source || parsed.provider || "json");
      const body = String(parsed.answer || parsed.explanation || parsed.text || text);
      const diagnostics = Array.isArray(parsed.diagnostics)
        ? parsed.diagnostics.map((item) => String(item))
        : [];
      return { source, body, diagnostics };
    }
  } catch {
    return {
      source: "texte",
      body: text,
      diagnostics: [],
    };
  }

  return {
    source: "texte",
    body: text,
    diagnostics: [],
  };
}

export function getFilteredPackets() {
  const q = String(state.packetFilter || "").trim().toLowerCase();
  return state.packets.filter((packet) => {
    if (!packetMatchesActiveLayers(packet)) {
      return false;
    }
    if (!q) {
      return true;
    }
    const flow =
      `${packet.source}:${formatOptional(packet.source_port, "?")} ` +
      `${packet.destination}:${formatOptional(packet.destination_port, "?")}`.toLowerCase();
    const macs = `${packet.source_mac || ""} ${packet.destination_mac || ""}`.toLowerCase();
    const proto = `${packet.ip_version}/${packet.protocol}`.toLowerCase();
    const size = String(packet.length || "");
    const info = String(packet.info || "").toLowerCase();
    return flow.includes(q) || macs.includes(q) || proto.includes(q) || size.includes(q) || info.includes(q);
  });
}

export function totalPages() {
  return Math.max(1, Math.ceil(getFilteredPackets().length / state.pageSize));
}

export function getPagedPackets(page) {
  const filtered = getFilteredPackets();
  const total = filtered.length;
  if (total === 0) {
    return [];
  }

  const start = (page - 1) * state.pageSize;
  const output = [];
  for (let offset = 0; offset < state.pageSize; offset += 1) {
    const position = start + offset;
    if (position >= total) {
      break;
    }
    output.push(filtered[position]);
  }
  return output;
}
