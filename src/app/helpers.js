import { KNOWN_PORTS, PAGE_SIZE, state } from "./domState.js";

const APPLICATION_PORTS = new Set([
  20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 587, 993, 995, 3306, 5432, 6379, 8080, 8443,
]);

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

export function packetMatchesLayer(packet, layer) {
  const selectedLayer = String(layer || "application").toLowerCase();
  const proto = protocolFamily(packet);
  const ip = ipFamily(packet);
  const isArp = proto === "ARP" || ip === "ARP";

  switch (selectedLayer) {
    case "application":
      return isApplicationPacket(packet);
    case "presentation":
      return isApplicationPacket(packet);
    case "session":
      return isApplicationPacket(packet);
    case "transport":
      return proto === "TCP" || proto === "UDP";
    case "network":
      return ip === "IPV4" || ip === "IPV6" || proto === "ICMP" || proto === "ICMPV6";
    case "datalink":
      return isArp;
    case "physical":
      return isArp;
    default:
      return true;
  }
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
    if (!packetMatchesLayer(packet, state.activeLayer)) {
      return false;
    }
    if (!q) {
      return true;
    }
    const flow =
      `${packet.source}:${formatOptional(packet.source_port, "?")} ` +
      `${packet.destination}:${formatOptional(packet.destination_port, "?")}`.toLowerCase();
    const proto = `${packet.ip_version}/${packet.protocol}`.toLowerCase();
    const size = String(packet.length || "");
    const info = String(packet.info || "").toLowerCase();
    return flow.includes(q) || proto.includes(q) || size.includes(q) || info.includes(q);
  });
}

export function totalPages() {
  return Math.max(1, Math.ceil(getFilteredPackets().length / PAGE_SIZE));
}

export function getPagedPackets(page) {
  const filtered = getFilteredPackets();
  const total = filtered.length;
  if (total === 0) {
    return [];
  }

  const start = (page - 1) * PAGE_SIZE;
  const output = [];
  for (let offset = 0; offset < PAGE_SIZE; offset += 1) {
    const position = start + offset;
    if (position >= total) {
      break;
    }
    output.push(filtered[total - 1 - position]);
  }
  return output;
}
