import { formatBytes, t } from "./i18n.js";
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
  l7: "L7",
  l6: "L6",
  l5: "L5",
  l4: "L4",
  l3: "L3",
  l2: "L2",
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

  pageText.textContent = t("table.page", { current: state.currentPage, total: pages });
  if (pageSummary) {
    if (filteredCount === 0) {
      pageSummary.textContent = t("table.summary.empty");
    } else {
      const start = (state.currentPage - 1) * state.pageSize + 1;
      const end = Math.min(filteredCount, state.currentPage * state.pageSize);
      pageSummary.textContent = t("table.summary.range", { start, end, count: filteredCount });
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
  const title = isSource ? t("th.source") : t("th.dest");

  const html = `
    <span class="cell-flow">${escapeHtml(ip)}</span>
    <span class="cell-sub">${escapeHtml(t("table.port"))} ${escapeHtml(formatOptional(port, "?"))} • ${escapeHtml(service)}</span>
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
    `${t("table.tip.network.layer")}: ${packet.ip_version}`,
    `${t("table.tip.transport.layer")}: ${packet.protocol}`,
    `${t("table.tip.layers.detected")}: ${layers.map((layerKey) => `${LAYER_LABELS[layerKey]} ${t(`layer.${layerKey}`)}`).join(" → ") || t("table.tip.unknown")}`,
    `TTL/Hop: ${packet.ttl_or_hop_limit ?? t("table.tip.unavailable")}`,
    `TCP ${t("table.tip.flags")}: ${packet.tcp_flags || "-"}`,
    `${t("table.tip.description")}: ${describeProtocol(packet.protocol)}`,
    `L6 ${t("table.tip.presentation")}: ${
      heuristics.presentation.matched ? `${t("table.tip.detected")} (${heuristics.presentation.confidence})` : t("table.tip.not.detected")
    }`,
    `L6 ${t("table.tip.false.positive")}: ${heuristics.presentation.falsePositiveRisk} (${heuristics.presentation.falsePositiveNote})`,
    `L5 ${t("table.tip.session")}: ${heuristics.session.matched ? `${t("table.tip.detected")} (${heuristics.session.confidence})` : t("table.tip.not.detected")}`,
    `L5 ${t("table.tip.false.positive")}: ${heuristics.session.falsePositiveRisk} (${heuristics.session.falsePositiveNote})`,
  ].join("\n");

  return createCell(html, tip);
}

function buildStageCell(packet) {
  const flags = parseTcpFlags(packet.tcp_flags);
  const stages = [];
  let narrative = t("stage.observed");

  if (isDnsPacket(packet)) {
    stages.push("DNS");
    narrative = t("stage.dns");
  }

  if (flags.has("SYN") && !flags.has("ACK")) {
    stages.push("SYN");
    narrative = t("stage.syn");
  } else if (flags.has("SYN") && flags.has("ACK")) {
    stages.push("SYN-ACK");
    narrative = t("stage.synack");
  } else if (flags.has("ACK") && !flags.has("SYN") && !flags.has("PSH")) {
    stages.push("ACK");
    narrative = t("stage.ack");
  }

  const tlsStage = detectTlsStage(packet);
  if (tlsStage === "client_hello") {
    stages.push("TLS CH");
    narrative = t("stage.tls.client");
  } else if (tlsStage === "server_hello") {
    stages.push("TLS SH");
    narrative = t("stage.tls.server");
  } else if (tlsStage === "record") {
    stages.push("TLS");
    narrative = t("stage.tls.record");
  }

  if (isLikelyDataPacket(packet)) {
    stages.push("DATA");
    narrative = t("stage.data");
  }

  if (flags.has("FIN")) {
    stages.push("FIN");
    narrative = t("stage.fin");
  }
  if (flags.has("RST")) {
    stages.push("RST");
    narrative = t("stage.rst");
  }

  const uniqueStages = Array.from(new Set(stages));
  const main = uniqueStages.length > 0 ? uniqueStages.slice(0, 4).join(" • ") : t("stage.obs");
  const html = `
    <span class="story-main">${escapeHtml(main)}</span>
    <span class="cell-sub">${escapeHtml(narrative)}</span>
  `;
  const tip = [
    `Story: ${main}`,
    `${t("table.tip.detail")}: ${narrative}`,
    `Conversation: ${conversationKeyForPacket(packet)}`,
    `Info: ${packet.info}`,
  ].join("\n");
  return createCell(html, tip, "stage-cell");
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
  const html = `<span class="size-pill">${formatBytes(packet.length ?? 0)}</span>`;
  const tip = `${t("table.tip.captured.size")}: ${packet.length} ${t("size.b")}\nEtherType: ${packet.ethertype}\nHex: ${packet.raw_hex}`;
  return createCell(html, tip);
}

export function renderTablePage() {
  renderPageControls();
  packetBody.innerHTML = "";

  const pagePackets = getPagedPackets(state.currentPage);
  if (pagePackets.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="7">${escapeHtml(t("table.empty"))}</td>`;
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
        `${t("table.tip.session.id")}: ${packet.id}\nTimestamp: ${packet.timestamp}\nInfo: ${packet.info}`,
      ),
    );
    tr.appendChild(
      createCell(
        escapeHtml(packet.timestamp),
        `${t("table.tip.raw.timestamp")}: ${packet.timestamp}\n${t("table.tip.length")}: ${packet.length} ${t("size.b")}`,
      ),
    );
    tr.appendChild(buildEndpointCell(packet, "source"));
    tr.appendChild(buildEndpointCell(packet, "destination"));
    tr.appendChild(buildProtocolCell(packet));
    tr.appendChild(buildStageCell(packet));
    tr.appendChild(buildSizeCell(packet));

    tr.addEventListener("click", () => {
      void onPacketSelect(packet);
    });

    packetBody.appendChild(tr);
  }
}

export function findPacketById(packetId) {
  return state.packetMap.get(packetId) ?? null;
}
