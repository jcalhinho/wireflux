import {
  conversationKeyForPacket,
  nextPageBtn,
  packetBody,
  pageText,
  prevPageBtn,
  state,
} from "./domState.js";
import {
  describeProtocol,
  escapeHtml,
  formatOptional,
  getPagedPackets,
  serviceNameForPort,
  totalPages,
} from "./helpers.js";

let onPacketSelect = async () => {};

export function setTableHooks(hooks) {
  onPacketSelect = hooks?.onPacketSelect || onPacketSelect;
}

export function renderPageControls() {
  const pages = totalPages();
  if (state.currentPage > pages) {
    state.currentPage = pages;
  }

  pageText.textContent = `Page ${state.currentPage} / ${pages}`;
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

function buildFlowCell(packet) {
  const sourcePort = formatOptional(packet.source_port, "?");
  const destinationPort = formatOptional(packet.destination_port, "?");
  const flowLabel = `${packet.source} -> ${packet.destination}`;
  const portsLabel = `${sourcePort} -> ${destinationPort}`;

  const html = `
    <span class="cell-flow">${escapeHtml(flowLabel)}</span>
    <span class="cell-sub">ports ${escapeHtml(portsLabel)}</span>
  `;

  const tip = [
    `Source: ${packet.source}:${sourcePort}`,
    `Destination: ${packet.destination}:${destinationPort}`,
    `Service destination: ${serviceNameForPort(packet.destination_port)}`,
    `Service source: ${serviceNameForPort(packet.source_port)}`,
    `Info: ${packet.info}`,
    `Conversation: ${conversationKeyForPacket(packet)}`,
  ].join("\n");

  return createCell(html, tip);
}

function buildProtocolCell(packet) {
  const label = `${packet.ip_version}/${packet.protocol}`;
  const html = `<span class="proto-pill">${escapeHtml(label)}</span>`;
  const tip = [
    `Couche réseau: ${packet.ip_version}`,
    `Couche transport: ${packet.protocol}`,
    `TTL/Hop: ${packet.ttl_or_hop_limit ?? "non disponible"}`,
    `Flags TCP: ${packet.tcp_flags || "-"}`,
    `Description: ${describeProtocol(packet.protocol)}`,
  ].join("\n");

  return createCell(html, tip);
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
    tr.innerHTML = "<td colspan=\"5\">Aucun paquet pour l'instant.</td>";
    packetBody.appendChild(tr);
    return;
  }

  for (const packet of pagePackets) {
    const tr = document.createElement("tr");
    tr.dataset.packetId = String(packet.id);
    tr.dataset.selected = String(packet.id === state.selectedPacketId);
    tr.dataset.proto = String(packet.protocol || "").toUpperCase();

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
    tr.appendChild(buildFlowCell(packet));
    tr.appendChild(buildProtocolCell(packet));
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
