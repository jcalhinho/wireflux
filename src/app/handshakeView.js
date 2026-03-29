import { handshakeView, state } from "./domState.js";
import { detectTlsStage, escapeHtml, isLikelyDataPacket, isTlsPort, parseTcpFlags } from "./helpers.js";

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
      '<div class="handshake-empty">Sélectionne une conversation dans la Flow Map pour voir le handshake TCP/TLS.</div>';
    return;
  }

  const convo = state.conversations.get(state.selectedConversationKey);
  if (!convo) {
    handshakeView.innerHTML = '<div class="handshake-empty">Conversation introuvable.</div>';
    return;
  }

  const steps = [
    {
      id: "tcp_syn",
      title: "SYN",
      description: "Client ouvre la connexion TCP",
      done: convo.stages.tcpSyn,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("SYN") && !flags.has("ACK");
      }),
    },
    {
      id: "tcp_syn_ack",
      title: "SYN-ACK",
      description: "Serveur accepte l'ouverture",
      done: convo.stages.tcpSynAck,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("SYN") && flags.has("ACK");
      }),
    },
    {
      id: "tcp_ack",
      title: "ACK",
      description: "Client confirme: session TCP établie",
      done: convo.stages.tcpAck,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("ACK") && !flags.has("SYN");
      }),
    },
    {
      id: "tls_client_hello",
      title: "ClientHello",
      description: "Négociation TLS initiée par le client",
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
      title: "ServerHello",
      description: "Réponse TLS serveur, paramètres crypto proposés",
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
      title: "Data",
      description: "Transfert applicatif après établissement du canal",
      done: convo.stages.data,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        return packet ? isLikelyDataPacket(packet) : false;
      }),
    },
  ];

  const completed = steps.filter((step) => step.done).length;
  const progress = Math.round((completed / steps.length) * 100);

  const progressWrap = document.createElement("div");
  progressWrap.className = "handshake-progress";
  progressWrap.innerHTML = `
    <span>${escapeHtml(convo.protocol)} • progression ${progress}%</span>
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
      meta.textContent = `vu sur paquet #${step.packetId}`;
    } else if (step.optional) {
      meta.textContent = "optionnel pour ce flow";
    } else {
      meta.textContent = "en attente";
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
