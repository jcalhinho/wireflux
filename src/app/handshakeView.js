import { handshakeView, state } from "./domState.js";
import { detectTlsStage, escapeHtml, isLikelyDataPacket, isTlsPort, parseTcpFlags } from "./helpers.js";
import { t } from "./i18n.js";

let onPacketSelect = async () => {};
let findPacketById = () => null;

export function setHandshakeHooks(hooks) {
  onPacketSelect = hooks?.onPacketSelect || onPacketSelect;
  findPacketById = hooks?.findPacketById || findPacketById;
}

export function renderHandshakeDecoder() {
  handshakeView.innerHTML = "";

  if (!state.selectedConversationKey) {
    handshakeView.innerHTML =
      `<div class="handshake-empty">${escapeHtml(t("handshake.empty.selectFlow"))}</div>`;
    return;
  }

  const convo = state.conversations.get(state.selectedConversationKey);
  if (!convo) {
    handshakeView.innerHTML = `<div class="handshake-empty">${escapeHtml(t("handshake.empty.notFound"))}</div>`;
    return;
  }

  const steps = [
    {
      id: "tcp_syn",
      title: t("handshake.step.syn.title"),
      description: t("handshake.step.syn.desc"),
      done: convo.stages.tcpSyn,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("SYN") && !flags.has("ACK");
      }),
    },
    {
      id: "tcp_syn_ack",
      title: t("handshake.step.synack.title"),
      description: t("handshake.step.synack.desc"),
      done: convo.stages.tcpSynAck,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("SYN") && flags.has("ACK");
      }),
    },
    {
      id: "tcp_ack",
      title: t("handshake.step.ack.title"),
      description: t("handshake.step.ack.desc"),
      done: convo.stages.tcpAck,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("ACK") && !flags.has("SYN");
      }),
    },
    {
      id: "tls_client_hello",
      title: t("handshake.step.ch.title"),
      description: t("handshake.step.ch.desc"),
      done: convo.stages.tlsClientHello,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        return packet ? detectTlsStage(packet) === "client_hello" : false;
      }),
      optional: !isTlsPort({
        destination_port: convo.destinationPort,
        source_port: convo.sourcePort,
      }),
    },
    {
      id: "tls_server_hello",
      title: t("handshake.step.sh.title"),
      description: t("handshake.step.sh.desc"),
      done: convo.stages.tlsServerHello,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        return packet ? detectTlsStage(packet) === "server_hello" : false;
      }),
      optional: !isTlsPort({
        destination_port: convo.destinationPort,
        source_port: convo.sourcePort,
      }),
    },
    {
      id: "data",
      title: t("handshake.step.data.title"),
      description: t("handshake.step.data.desc"),
      done: convo.stages.data,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        return packet ? isLikelyDataPacket(packet) : false;
      }),
    },
  ];

  const completed = steps.filter((step) => step.done).length;
  const progress = Math.round((completed / steps.length) * 100);
  const flowLabel = `${convo.source}:${convo.sourcePort ?? "?"} -> ${convo.destination}:${convo.destinationPort ?? "?"}`;
  const interpretation =
    progress >= 80
      ? t("handshake.interpretation.complete")
      : progress >= 45
        ? t("handshake.interpretation.progress")
        : t("handshake.interpretation.partial");

  const guide = document.createElement("div");
  guide.className = "handshake-guide";
  guide.innerHTML = `
    <strong>${escapeHtml(t("handshake.guide.activeFlow", { flow: flowLabel }))}</strong>
    <p>${escapeHtml(t("handshake.guide.steps"))}</p>
    <p>${escapeHtml(interpretation)}</p>
    <p>${escapeHtml(t("handshake.guide.click"))}</p>
  `;
  handshakeView.appendChild(guide);

  const progressWrap = document.createElement("div");
  progressWrap.className = "handshake-progress";
  progressWrap.innerHTML = `
    <span>${escapeHtml(t("handshake.progress", { protocol: convo.protocol, progress }))}</span>
    <div class="handshake-progress-track">
      <div class="handshake-progress-fill" style="width:${progress}%"></div>
    </div>
  `;
  handshakeView.appendChild(progressWrap);

  const grid = document.createElement("div");
  grid.className = "handshake-steps";

  steps.forEach((step, index) => {
    const block = document.createElement("div");
    block.className = "handshake-step";
    block.style.setProperty("--step-index", String(index));
    if (step.done) {
      block.classList.add("is-done");
    }
    if (step.optional) {
      block.classList.add("is-optional");
    }

    const title = document.createElement("strong");
    title.textContent = step.title;

    const description = document.createElement("p");
    description.textContent = step.description;

    const meta = document.createElement("small");
    if (step.packetId) {
      meta.textContent = t("handshake.meta.seen", { id: step.packetId });
    } else if (step.optional) {
      meta.textContent = t("handshake.meta.optional");
    } else {
      meta.textContent = t("handshake.meta.pending");
    }

    block.appendChild(title);
    block.appendChild(description);
    block.appendChild(meta);

    if (step.packetId) {
      block.addEventListener("click", () => {
        const packet = findPacketById(step.packetId);
        if (packet) {
          void onPacketSelect(packet);
        }
      });
      block.dataset.tip = `${step.title}\n${step.description}\nPaquet #${step.packetId}`;
    } else {
      block.dataset.tip = `${step.title}\n${step.description}`;
    }

    grid.appendChild(block);
  });

  handshakeView.appendChild(grid);
}
