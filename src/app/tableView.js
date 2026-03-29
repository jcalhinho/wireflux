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
  describeProtocol,
  escapeHtml,
  formatOptional,
  getFilteredPackets,
  getPagedPackets,
  resolveOsiLayer,
  serviceNameForPort,
  totalPages,
} from "./helpers.js";

let onPacketSelect = async () => {};

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
  const service = serviceNameForPort(port);
  const title = isSource ? "Source" : "Destination";

  const html = `
    <span class="cell-flow">${escapeHtml(ip)}</span>
    <span class="cell-sub">port ${escapeHtml(formatOptional(port, "?"))} • ${escapeHtml(service)}</span>
  `;
  const tip = [
    `${title}: ${ip}:${formatOptional(port, "?")}`,
    `Service: ${service}`,
    `Conversation: ${conversationKeyForPacket(packet)}`,
    `Info: ${packet.info}`,
  ].join("\n");
  return createCell(html, tip);
}

function buildProtocolCell(packet) {
  const label = `${packet.ip_version}/${packet.protocol}`;
  const layer = resolveOsiLayer(packet);
  const html = `<span class="proto-pill" data-layer="${layer}">${escapeHtml(label)}</span>`;
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
    tr.innerHTML = "<td colspan=\"6\">Aucun paquet pour l'instant.</td>";
    packetBody.appendChild(tr);
    return;
  }

  for (const packet of pagePackets) {
    const tr = document.createElement("tr");
    tr.dataset.packetId = String(packet.id);
    tr.dataset.selected = String(packet.id === state.selectedPacketId);
    tr.dataset.proto = String(packet.protocol || "").toUpperCase();
    tr.dataset.osiLayer = resolveOsiLayer(packet);

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
