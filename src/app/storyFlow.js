import {
  MAX_FLOW_ITEMS,
  MAX_STORY_EVENTS,
  conversationKeyForPacket,
  flowMap,
  state,
  storyList,
} from "./domState.js";
import {
  clamp,
  escapeHtml,
  formatOptional,
  detectTlsStage,
  isDnsPacket,
  isLikelyDataPacket,
  packetMatchesLayer,
  parseTcpFlags,
  parseTimestampValue,
} from "./helpers.js";

let onPacketSelect = async () => {};
let findPacketById = () => null;

export function setStoryFlowHooks(hooks) {
  onPacketSelect = hooks?.onPacketSelect || onPacketSelect;
  findPacketById = hooks?.findPacketById || findPacketById;
}

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
      stats: {
        syn: 0,
        synAck: 0,
        ack: 0,
        fin: 0,
        rst: 0,
        dns: 0,
        tls: 0,
        data: 0,
      },
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
  if (packet.destination_port !== null && packet.destination_port !== undefined) {
    convo.ports.add(packet.destination_port);
  }
  if (packet.source_port !== null && packet.source_port !== undefined) {
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

function pushStoryEvent(stage, label, detail, packet, conversationKey) {
  const key = `${conversationKey}|${stage}|${packet.id}`;
  if (state.storySeen.has(key)) {
    return;
  }

  state.storySeen.add(key);
  state.storyEvents.push({
    key,
    stage,
    label,
    detail,
    packetId: packet.id,
    timestamp: packet.timestamp,
    conversationKey,
  });

  if (state.storyEvents.length > MAX_STORY_EVENTS) {
    const removed = state.storyEvents.shift();
    if (removed) {
      state.storySeen.delete(removed.key);
    }
  }
}

export function processStoryEvent(packet, convo) {
  const convoKey = convo.key;
  const flags = parseTcpFlags(packet.tcp_flags);

  if (isDnsPacket(packet)) {
    pushStoryEvent(
      "dns",
      "DNS",
      `Résolution DNS observée (${packet.source} -> ${packet.destination}).`,
      packet,
      convoKey,
    );
  }

  if (flags.has("SYN") && !flags.has("ACK")) {
    pushStoryEvent(
      "tcp_syn",
      "TCP SYN",
      `Tentative d'ouverture TCP vers ${packet.destination}:${formatOptional(packet.destination_port, "?")}.`,
      packet,
      convoKey,
    );
  }

  if (flags.has("SYN") && flags.has("ACK")) {
    pushStoryEvent(
      "tcp_syn_ack",
      "TCP SYN-ACK",
      `Réponse SYN-ACK détectée depuis ${packet.source}:${formatOptional(packet.source_port, "?")}.`,
      packet,
      convoKey,
    );
  }

  if (flags.has("ACK") && convo.stages.tcpSynAck && !flags.has("SYN")) {
    pushStoryEvent(
      "tcp_ack",
      "TCP ACK",
      "Handshake TCP probablement complété (ACK final).",
      packet,
      convoKey,
    );
  }

  const tlsStage = detectTlsStage(packet);
  if (tlsStage === "client_hello") {
    pushStoryEvent(
      "tls_client_hello",
      "TLS ClientHello",
      "Démarrage de la négociation TLS côté client.",
      packet,
      convoKey,
    );
  } else if (tlsStage === "server_hello") {
    pushStoryEvent(
      "tls_server_hello",
      "TLS ServerHello",
      "Réponse TLS serveur observée.",
      packet,
      convoKey,
    );
  } else if (tlsStage === "record") {
    pushStoryEvent("tls_record", "TLS Record", "Trafic TLS chiffré détecté.", packet, convoKey);
  }

  if (isLikelyDataPacket(packet)) {
    pushStoryEvent(
      "data",
      "Data",
      `Données applicatives en transit (${packet.length} octets).`,
      packet,
      convoKey,
    );
  }
}

function flowNormalityScore(convo) {
  let score = 100;
  if (convo.stats.syn > 0 && convo.stats.synAck === 0) {
    score -= 18;
  }
  if (convo.stats.syn > 0 && convo.stats.synAck > 0 && convo.stats.ack === 0) {
    score -= 14;
  }
  if (convo.stats.rst > Math.max(4, Math.floor(convo.packets * 0.22))) {
    score -= 24;
  }
  if ((convo.ports.has(443) || convo.ports.has(8443)) && convo.stats.tls === 0 && convo.packets > 6) {
    score -= 16;
  }
  if (convo.stats.data > 0 && convo.stats.syn === 0 && convo.protocol === "TCP") {
    score -= 12;
  }
  if (convo.stats.fin === 0 && convo.packets > 20 && convo.protocol === "TCP") {
    score -= 8;
  }
  if (convo.packets < 3) {
    score -= 6;
  }
  return clamp(Math.round(score), 5, 100);
}

function scoreBand(score) {
  if (score >= 78) {
    return "good";
  }
  if (score >= 50) {
    return "warn";
  }
  return "risk";
}

export function renderFlowMap() {
  flowMap.innerHTML = "";

  const items = Array.from(state.conversations.values())
    .filter((convo) =>
      packetMatchesLayer(
        {
          protocol: convo.protocol,
          ip_version: convo.ipVersion,
          source_port: convo.sourcePort,
          destination_port: convo.destinationPort,
          info: "",
        },
        state.activeLayer,
      ),
    )
    .sort((a, b) => b.packets - a.packets)
    .slice(0, MAX_FLOW_ITEMS);

  if (items.length === 0) {
    flowMap.innerHTML = '<div class="flow-empty">Les conversations actives apparaîtront ici.</div>';
    return;
  }

  for (const convo of items) {
    const score = flowNormalityScore(convo);
    const band = scoreBand(score);

    const card = document.createElement("button");
    card.type = "button";
    card.className = `flow-card flow-${band}`;
    if (state.selectedConversationKey === convo.key) {
      card.classList.add("is-selected");
    }
    card.dataset.tip = `Conversation: ${convo.key}\nScore de normalité: ${score}/100`;

    const top = document.createElement("div");
    top.className = "flow-top";

    const labelWrap = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent =
      `${convo.source}:${formatOptional(convo.sourcePort, "?")} -> ` +
      `${convo.destination}:${formatOptional(convo.destinationPort, "?")}`;
    const sub = document.createElement("div");
    sub.className = "flow-sub";
    sub.textContent = `${convo.protocol} • ${convo.packets} paquets • ${convo.bytes} octets`;
    labelWrap.appendChild(strong);
    labelWrap.appendChild(sub);

    const scoreBadge = document.createElement("span");
    scoreBadge.className = "flow-score-badge";
    scoreBadge.textContent = `${score}/100`;

    top.appendChild(labelWrap);
    top.appendChild(scoreBadge);

    const track = document.createElement("div");
    track.className = "flow-score-track";
    const fill = document.createElement("div");
    fill.className = "flow-score-fill";
    fill.style.width = `${score}%`;
    track.appendChild(fill);

    card.appendChild(top);
    card.appendChild(track);

    card.addEventListener("click", () => {
      state.selectedConversationKey = convo.key;
      renderFlowMap();
      renderStoryList();
      renderHandshakeDecoder();
      const packet = findPacketById(convo.packetIds[convo.packetIds.length - 1]);
      if (packet) {
        void onPacketSelect(packet);
      }
    });

    flowMap.appendChild(card);
  }
}

function stageLabel(stage) {
  switch (stage) {
    case "dns":
      return "DNS";
    case "tcp_syn":
      return "TCP SYN";
    case "tcp_syn_ack":
      return "TCP SYN-ACK";
    case "tcp_ack":
      return "TCP ACK";
    case "tls_client_hello":
      return "TLS ClientHello";
    case "tls_server_hello":
      return "TLS ServerHello";
    case "tls_record":
      return "TLS Record";
    case "data":
      return "Data";
    default:
      return "Événement";
  }
}

export function renderStoryList() {
  storyList.innerHTML = "";

  let events = state.storyEvents.filter((event) => {
    const packet = findPacketById(event.packetId);
    if (!packet) {
      return false;
    }
    return packetMatchesLayer(packet, state.activeLayer);
  });
  if (state.selectedConversationKey) {
    const filtered = state.storyEvents.filter((event) => event.conversationKey === state.selectedConversationKey);
    const layerFiltered = filtered.filter((event) => {
      const packet = findPacketById(event.packetId);
      if (!packet) {
        return false;
      }
      return packetMatchesLayer(packet, state.activeLayer);
    });
    if (layerFiltered.length > 0) {
      events = layerFiltered;
    }
  }

  if (events.length === 0) {
    storyList.innerHTML = '<li class="story-empty">La timeline se remplira pendant la capture.</li>';
    return;
  }

  const recent = events.slice(-40).reverse();
  for (const event of recent) {
    const item = document.createElement("li");
    item.className = `story-item stage-${event.stage}`;
    item.dataset.tip = `${stageLabel(event.stage)}\n${event.detail}`;

    const badge = document.createElement("span");
    badge.className = "story-badge";
    badge.textContent = stageLabel(event.stage);

    const content = document.createElement("div");
    content.className = "story-content";

    const title = document.createElement("strong");
    title.textContent = event.label;

    const detail = document.createElement("p");
    detail.textContent = event.detail;

    const meta = document.createElement("small");
    meta.textContent = `Paquet #${event.packetId} • ${event.timestamp}`;

    content.appendChild(title);
    content.appendChild(detail);
    content.appendChild(meta);

    item.appendChild(badge);
    item.appendChild(content);

    item.addEventListener("click", () => {
      const packet = findPacketById(event.packetId);
      if (packet) {
        void onPacketSelect(packet);
      }
    });

    storyList.appendChild(item);
  }
}
