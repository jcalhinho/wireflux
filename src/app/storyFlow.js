import { conversationKeyForPacket, state } from "./domState.js";
import {
  detectTlsStage,
  isDnsPacket,
  isLikelyDataPacket,
  parseTcpFlags,
  parseTimestampValue,
} from "./helpers.js";

export function ensureConversation(packet) {
  const key = conversationKeyForPacket(packet);
  let convo = state.conversations.get(key);
  if (!convo) {
    convo = {
      key,
      source: packet.source,
      destination: packet.destination,
      sourcePort: packet.source_port,
      destinationPort: packet.destination_port,
      protocol: packet.protocol,
      ipVersion: packet.ip_version,
      firstSeen: parseTimestampValue(packet.timestamp),
      lastSeen: parseTimestampValue(packet.timestamp),
      packets: 0,
      bytes: 0,
      stats: { syn: 0, synAck: 0, ack: 0, fin: 0, rst: 0, dns: 0, tls: 0, data: 0 },
      stages: {
        dns: false,
        tcpSyn: false,
        tcpSynAck: false,
        tcpAck: false,
        tlsClientHello: false,
        tlsServerHello: false,
        data: false,
      },
      packetIds: [],
      ports: new Set(),
    };
    state.conversations.set(key, convo);
  }

  convo.packets += 1;
  convo.bytes += packet.length || 0;
  convo.lastSeen = parseTimestampValue(packet.timestamp);
  convo.packetIds.push(packet.id);
  if (convo.packetIds.length > 200) {
    convo.packetIds.shift();
  }
  if (packet.destination_port != null) {
    convo.ports.add(packet.destination_port);
  }
  if (packet.source_port != null) {
    convo.ports.add(packet.source_port);
  }

  const flags = parseTcpFlags(packet.tcp_flags);
  if (flags.has("SYN") && !flags.has("ACK")) {
    convo.stats.syn += 1;
    convo.stages.tcpSyn = true;
  }
  if (flags.has("SYN") && flags.has("ACK")) {
    convo.stats.synAck += 1;
    convo.stages.tcpSynAck = true;
  }
  if (flags.has("ACK")) {
    convo.stats.ack += 1;
    if (convo.stages.tcpSynAck) {
      convo.stages.tcpAck = true;
    }
  }
  if (flags.has("FIN")) {
    convo.stats.fin += 1;
  }
  if (flags.has("RST")) {
    convo.stats.rst += 1;
  }
  if (isDnsPacket(packet)) {
    convo.stats.dns += 1;
    convo.stages.dns = true;
  }
  const tlsStage = detectTlsStage(packet);
  if (tlsStage) {
    convo.stats.tls += 1;
  }
  if (tlsStage === "client_hello") {
    convo.stages.tlsClientHello = true;
  }
  if (tlsStage === "server_hello") {
    convo.stages.tlsServerHello = true;
  }
  if (isLikelyDataPacket(packet)) {
    convo.stats.data += 1;
    convo.stages.data = true;
  }

  return convo;
}
