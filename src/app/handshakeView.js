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
      '<div class="handshake-empty">Clique d\'abord un item dans "Flow Map Interactive": cela sélectionne un flux précis et aligne ce décodeur sur ce flux.</div>';
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
      title: "1) SYN",
      description: "Le client demande l'ouverture d'une connexion",
      done: convo.stages.tcpSyn,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("SYN") && !flags.has("ACK");
      }),
    },
    {
      id: "tcp_syn_ack",
      title: "2) SYN-ACK",
      description: "Le serveur répond qu'il est prêt",
      done: convo.stages.tcpSynAck,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("SYN") && flags.has("ACK");
      }),
    },
    {
      id: "tcp_ack",
      title: "3) ACK",
      description: "Le client confirme, la connexion TCP est établie",
      done: convo.stages.tcpAck,
      packetId: convo.packetIds.find((id) => {
        const packet = findPacketById(id);
        const flags = packet ? parseTcpFlags(packet.tcp_flags) : new Set();
        return flags.has("ACK") && !flags.has("SYN");
      }),
    },
    {
      id: "tls_client_hello",
      title: "4) ClientHello",
      description: "Début du chiffrement TLS (si HTTPS)",
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
      title: "5) ServerHello",
      description: "Le serveur choisit les paramètres de chiffrement",
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
      title: "6) Data",
      description: "Les données applicatives circulent",
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
      ? "Session majoritairement complète."
      : progress >= 45
        ? "Session en cours de construction."
        : "Début de session ou flux partiel.";

  const guide = document.createElement("div");
  guide.className = "handshake-guide";
  guide.innerHTML = `
    <strong>Flux actif: ${escapeHtml(flowLabel)}</strong>
    <p>Étapes 1 à 3: ouverture TCP. Étapes 4 à 5: négociation TLS (si HTTPS). Étape 6: transfert de données.</p>
    <p>${escapeHtml(interpretation)}</p>
    <p>Clique une étape détectée pour ouvrir directement le paquet correspondant dans le tableau.</p>
  `;
  handshakeView.appendChild(guide);

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
      meta.textContent = `Vu sur paquet #${step.packetId}`;
    } else if (step.optional) {
      meta.textContent = "Optionnel pour ce flux";
    } else {
      meta.textContent = "Pas encore observé";
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
