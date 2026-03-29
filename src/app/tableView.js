import {
  conversationKeyForPacket,
  nextPageBtn,
  packetBody,
  pageSummary,
  pageText,
  prevPageBtn,
  state,
} from "./domState.js";
import {
  detectTlsStage,
  detectLayerHeuristics,
  describeProtocol,
  escapeHtml,
  formatOptional,
  getFilteredPackets,
  getPagedPackets,
  isDnsPacket,
  isLikelyDataPacket,
  parseTcpFlags,
  resolveOsiLayer,
  resolvePacketLayers,
  serviceNameForPort,
  totalPages,
} from "./helpers.js";

let onPacketSelect = async () => {};

const LAYER_COLORS = Object.freeze({
  l7: "#0d9466",
  l6: "#19a97d",
  l5: "#0ea5b8",
  l4: "#0f6df3",
  l3: "#d97706",
  l2: "#7c3aed",
});

const LAYER_LABELS = Object.freeze({
  l7: "L7 Application",
  l6: "L6 Présentation",
  l5: "L5 Session",
  l4: "L4 Transport",
  l3: "L3 Réseau",
  l2: "L2 Liaison",
});

export function setTableHooks(hooks) {
  onPacketSelect = hooks?.onPacketSelect || onPacketSelect;
}

export function renderPageControls() {
  const filteredCount = getFilteredPackets().length;
  const pages = totalPages();
  if (state.currentPage > pages) {
    state.currentPage = pages;
  }

  pageText.textContent = `Page ${state.currentPage} / ${pages}`;
  if (pageSummary) {
    if (filteredCount === 0) {
      pageSummary.textContent = "0 / 0";
    } else {
      const start = (state.currentPage - 1) * state.pageSize + 1;
      const end = Math.min(filteredCount, state.currentPage * state.pageSize);
      pageSummary.textContent = `${start}-${end} / ${filteredCount}`;
    }
  }
  prevPageBtn.disabled = state.currentPage <= 1;
  nextPageBtn.disabled = state.currentPage >= pages;
}

export { totalPages };

function createCell(content, tooltipText = "", className = "") {
  const td = document.createElement("td");
  if (className) {
    td.className = className;
  }

  if (typeof content === "string") {
    td.innerHTML = content;
  } else {
    td.appendChild(content);
  }

  if (tooltipText) {
    td.dataset.tip = tooltipText;
  }

  return td;
}

function buildEndpointCell(packet, side) {
  const isSource = side === "source";
  const ip = isSource ? packet.source : packet.destination;
  const port = isSource ? packet.source_port : packet.destination_port;
  const mac = String(isSource ? packet.source_mac : packet.destination_mac || "");
  const safeMac = mac && mac !== "unknown" ? mac : "-";
  const service = serviceNameForPort(port);
  const title = isSource ? "Source" : "Destination";

  const html = `
    <span class="cell-flow">${escapeHtml(ip)}</span>
    <span class="cell-sub">port ${escapeHtml(formatOptional(port, "?"))} • ${escapeHtml(service)}</span>
    <span class="cell-sub">MAC ${escapeHtml(safeMac)}</span>
  `;
  const tip = [
    `${title}: ${ip}:${formatOptional(port, "?")}`,
    `MAC: ${safeMac}`,
    `Service: ${service}`,
    `Conversation: ${conversationKeyForPacket(packet)}`,
    `Info: ${packet.info}`,
  ].join("\n");
  return createCell(html, tip);
}

function buildProtocolCell(packet) {
  const label = `${packet.ip_version}/${packet.protocol}`;
  const layers = resolvePacketLayers(packet);
  const heuristics = detectLayerHeuristics(packet);
  const primaryLayer = layers[0] || resolveOsiLayer(packet);
  const badges = layers
    .map((layerKey) => `<span class="layer-chip" data-layer="${layerKey}">${layerKey.toUpperCase()}</span>`)
    .join("");
  const chipsHtml = badges ? `<span class="layer-chip-row">${badges}</span>` : "";
  const html = `
    <div class="proto-stack">
      <span class="proto-pill" data-layer="${primaryLayer}">${escapeHtml(label)}</span>
      ${chipsHtml}
    </div>
  `;
  const tip = [
    `Couche réseau: ${packet.ip_version}`,
    `Couche transport: ${packet.protocol}`,
    `Couches détectées: ${layers.map((layerKey) => LAYER_LABELS[layerKey] || layerKey).join(" → ") || "inconnu"}`,
    `TTL/Hop: ${packet.ttl_or_hop_limit ?? "non disponible"}`,
    `Flags TCP: ${packet.tcp_flags || "-"}`,
    `Description: ${describeProtocol(packet.protocol)}`,
    `L6 présentation: ${
      heuristics.presentation.matched ? `détectée (${heuristics.presentation.confidence})` : "non détectée"
    }`,
    `L6 faux positifs: ${heuristics.presentation.falsePositiveRisk} (${heuristics.presentation.falsePositiveNote})`,
    `L5 session: ${heuristics.session.matched ? `détectée (${heuristics.session.confidence})` : "non détectée"}`,
    `L5 faux positifs: ${heuristics.session.falsePositiveRisk} (${heuristics.session.falsePositiveNote})`,
  ].join("\n");

  return createCell(html, tip);
}

function buildStoryCell(packet) {
  const flags = parseTcpFlags(packet.tcp_flags);
  const stages = [];
  let narrative = "Étape de flux observée.";

  if (isDnsPacket(packet)) {
    stages.push("DNS");
    narrative = "Résolution DNS.";
  }

  if (flags.has("SYN") && !flags.has("ACK")) {
    stages.push("SYN");
    narrative = "Ouverture TCP.";
  } else if (flags.has("SYN") && flags.has("ACK")) {
    stages.push("SYN-ACK");
    narrative = "Réponse handshake TCP.";
  } else if (flags.has("ACK") && !flags.has("SYN") && !flags.has("PSH")) {
    stages.push("ACK");
    narrative = "Confirmation de session.";
  }

  const tlsStage = detectTlsStage(packet);
  if (tlsStage === "client_hello") {
    stages.push("TLS CH");
    narrative = "Négociation TLS côté client.";
  } else if (tlsStage === "server_hello") {
    stages.push("TLS SH");
    narrative = "Négociation TLS côté serveur.";
  } else if (tlsStage === "record") {
    stages.push("TLS");
    narrative = "Trafic TLS chiffré.";
  }

  if (isLikelyDataPacket(packet)) {
    stages.push("DATA");
    narrative = "Données applicatives.";
  }

  if (flags.has("FIN")) {
    stages.push("FIN");
    narrative = "Fermeture de session.";
  }
  if (flags.has("RST")) {
    stages.push("RST");
    narrative = "Réinitialisation de session.";
  }

  const uniqueStages = Array.from(new Set(stages));
  const main = uniqueStages.length > 0 ? uniqueStages.slice(0, 4).join(" • ") : "OBS";
  const html = `
    <span class="story-main">${escapeHtml(main)}</span>
    <span class="cell-sub">${escapeHtml(narrative)}</span>
  `;
  const tip = [
    `Story: ${main}`,
    `Détail: ${narrative}`,
    `Conversation: ${conversationKeyForPacket(packet)}`,
    `Info: ${packet.info}`,
  ].join("\n");
  return createCell(html, tip, "story-cell");
}

function buildLayerGradient(layers) {
  const orderedLayers = Array.from(new Set(layers)).filter((layer) =>
    Object.prototype.hasOwnProperty.call(LAYER_COLORS, layer),
  );
  if (orderedLayers.length === 0) {
    return "transparent";
  }
  if (orderedLayers.length === 1) {
    return LAYER_COLORS[orderedLayers[0]];
  }

  const segments = [];
  const step = 100 / orderedLayers.length;
  for (let index = 0; index < orderedLayers.length; index += 1) {
    const layer = orderedLayers[index];
    const start = Number(index * step).toFixed(2);
    const end = Number((index + 1) * step).toFixed(2);
    const color = LAYER_COLORS[layer];
    segments.push(`${color} ${start}%`, `${color} ${end}%`);
  }
  return `linear-gradient(180deg, ${segments.join(", ")})`;
}

function buildSizeCell(packet) {
  const html = `<span class="size-pill">${packet.length} B</span>`;
  const tip = `Taille capturée: ${packet.length} octets\nEtherType: ${packet.ethertype}\nHex: ${packet.raw_hex}`;
  return createCell(html, tip);
}

export function renderTablePage() {
  renderPageControls();
  packetBody.innerHTML = "";

  const pagePackets = getPagedPackets(state.currentPage);
  if (pagePackets.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = "<td colspan=\"7\">Aucun paquet pour l'instant.</td>";
    packetBody.appendChild(tr);
    return;
  }

  for (const packet of pagePackets) {
    const layers = resolvePacketLayers(packet);
    const primaryLayer = layers[0] || resolveOsiLayer(packet);
    const tr = document.createElement("tr");
    tr.dataset.packetId = String(packet.id);
    tr.dataset.selected = String(packet.id === state.selectedPacketId);
    tr.dataset.proto = String(packet.protocol || "").toUpperCase();
    tr.dataset.osiLayer = primaryLayer;
    tr.dataset.osiLayers = layers.join(" ");
    tr.style.setProperty("--packet-layer-gradient", buildLayerGradient(layers));

    tr.appendChild(
      createCell(
        escapeHtml(String(packet.id)),
        `ID session: ${packet.id}\nTimestamp: ${packet.timestamp}\nInfo: ${packet.info}`,
      ),
    );
    tr.appendChild(
      createCell(
        escapeHtml(packet.timestamp),
        `Horodatage brut: ${packet.timestamp}\nLongueur: ${packet.length} octets`,
      ),
    );
    tr.appendChild(buildEndpointCell(packet, "source"));
    tr.appendChild(buildEndpointCell(packet, "destination"));
    tr.appendChild(buildProtocolCell(packet));
    tr.appendChild(buildStoryCell(packet));
    tr.appendChild(buildSizeCell(packet));

    tr.addEventListener("click", () => {
      void onPacketSelect(packet);
    });

    packetBody.appendChild(tr);
  }
}

export function findPacketById(packetId) {
  return state.packets.find((packet) => packet.id === packetId) || null;
}
