import {
  aiCacheKey,
  coachView,
  explanationView,
  resolveProfileMode,
  state,
  updateProfileStatus,
} from "./domState.js";
import {
  describeIpLayer,
  describeProtocol,
  describeTcpFlags,
  escapeHtml,
  formatOptional,
  isDnsPacket,
  isPrivateIp,
  isTlsPort,
  listItemsToHtml,
  parseAiResponse,
  parseTcpFlags,
  serviceNameForPort,
} from "./helpers.js";

let findPacketById = () => null;

export function setExplainHooks(hooks) {
  findPacketById = hooks?.findPacketById || findPacketById;
}

function createQuizForPacket(packet) {
  const proto = String(packet.protocol || "").toUpperCase();
  const flags = parseTcpFlags(packet.tcp_flags);

  if (proto === "TCP" && flags.has("SYN") && !flags.has("ACK")) {
    return {
      question: "Ce flag SYN sert à quoi ?",
      options: [
        { text: "À demander l'ouverture d'une connexion TCP", correct: true },
        { text: "À fermer proprement une connexion", correct: false },
        { text: "À signaler un paquet ICMP d'erreur", correct: false },
      ],
      explanation: "SYN lance le handshake TCP en proposant un numéro de séquence initial.",
    };
  }

  if (proto === "TCP" && flags.has("SYN") && flags.has("ACK")) {
    return {
      question: "SYN-ACK correspond à quelle étape ?",
      options: [
        { text: "Réponse du serveur dans le handshake TCP", correct: true },
        { text: "Envoi applicatif chiffré TLS", correct: false },
        { text: "Annonce de fermeture FIN", correct: false },
      ],
      explanation: "SYN-ACK est la deuxième étape: le serveur accepte la demande SYN.",
    };
  }

  if (proto === "TCP" && flags.has("PSH") && flags.has("ACK")) {
    return {
      question: "PSH + ACK indique généralement...",
      options: [
        { text: "Des données applicatives à livrer rapidement", correct: true },
        { text: "Une résolution DNS", correct: false },
        { text: "Un paquet ARP de broadcast", correct: false },
      ],
      explanation: "PSH pousse les données vers l'application sans attendre de buffering supplémentaire.",
    };
  }

  if (proto === "UDP" && (packet.destination_port === 53 || packet.source_port === 53)) {
    return {
      question: "Pourquoi DNS utilise souvent UDP/53 ?",
      options: [
        { text: "Moins de latence et overhead pour requêtes courtes", correct: true },
        { text: "Car UDP chiffre automatiquement le trafic", correct: false },
        { text: "Pour garantir l'ordre strict des paquets", correct: false },
      ],
      explanation: "UDP est léger pour des échanges courts, avec fallback TCP dans certains cas DNS.",
    };
  }

  if (packet.destination_port === 443 || packet.source_port === 443) {
    return {
      question: "Le port 443 est principalement associé à...",
      options: [
        { text: "HTTPS (HTTP sur TLS)", correct: true },
        { text: "SSH", correct: false },
        { text: "SMTP", correct: false },
      ],
      explanation: "443 est le port standard de HTTPS, généralement après handshake TCP puis TLS.",
    };
  }

  if (proto === "ICMP" || proto === "ICMPV6") {
    return {
      question: "ICMP sert surtout à...",
      options: [
        { text: "Le diagnostic et les messages de contrôle réseau", correct: true },
        { text: "Transporter des pages web", correct: false },
        { text: "Négocier TLS", correct: false },
      ],
      explanation: "ICMP/ICMPv6 transporte des messages de contrôle et de diagnostic (ex: ping).",
    };
  }

  return {
    question: "Dans l'analyse réseau, le couple port + protocole permet surtout de...",
    options: [
      { text: "Inférer le service probable et la phase d'échange", correct: true },
      { text: "Connaître automatiquement le mot de passe applicatif", correct: false },
      { text: "Éviter totalement toute inspection de payload", correct: false },
    ],
    explanation: "Le contexte (ports, flags, taille, direction) guide l'interprétation fonctionnelle des paquets.",
  };
}

export function renderCoach() {
  coachView.innerHTML = "";

  if (!state.coach.quiz) {
    coachView.innerHTML = '<div class="coach-empty">Sélectionne un paquet pour lancer un quiz contextuel.</div>';
    return;
  }

  const wrapper = document.createElement("article");
  wrapper.className = "coach-card";

  const title = document.createElement("h3");
  title.textContent = "Quiz contextuel";

  const question = document.createElement("p");
  question.className = "coach-question";
  question.textContent = state.coach.quiz.question;

  const options = document.createElement("div");
  options.className = "coach-options";

  state.coach.quiz.options.forEach((option, index) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "coach-option";
    btn.textContent = option.text;

    if (state.coach.answered) {
      if (option.correct) {
        btn.classList.add("is-correct");
      }
      if (state.coach.selectedIndex === index && !option.correct) {
        btn.classList.add("is-wrong");
      }
      btn.disabled = true;
    }

    btn.addEventListener("click", () => {
      if (state.coach.answered) {
        return;
      }

      state.coach.answered = true;
      state.coach.selectedIndex = index;
      state.quizAnswered += 1;
      if (option.correct) {
        state.quizCorrect += 1;
      }

      updateProfileStatus();
      renderCoach();

      if (state.selectedPacketId) {
        const packet = findPacketById(state.selectedPacketId);
        if (packet) {
          const model = state.selectedModel;
          const key = aiCacheKey(packet.id, model);
          const aiText = state.aiCache.get(key) || "";
          const aiError = state.aiErrorCache.get(key) || "";
          renderExplanation(packet, aiText, { aiError });
        }
      }
    });

    options.appendChild(btn);
  });

  const footer = document.createElement("div");
  footer.className = "coach-footer";

  const score = document.createElement("span");
  score.textContent = `Score session: ${state.quizCorrect}/${state.quizAnswered}`;

  footer.appendChild(score);

  if (state.coach.answered) {
    const explain = document.createElement("p");
    explain.className = "coach-explain";
    explain.textContent = state.coach.quiz.explanation;
    footer.appendChild(explain);
  }

  wrapper.appendChild(title);
  wrapper.appendChild(question);
  wrapper.appendChild(options);
  wrapper.appendChild(footer);

  coachView.appendChild(wrapper);
}

export function prepareCoach(packet) {
  state.coach.packetId = packet.id;
  state.coach.quiz = createQuizForPacket(packet);
  state.coach.answered = false;
  state.coach.selectedIndex = null;
  renderCoach();
}

function buildLearningHints(packet) {
  const hints = [];
  const proto = String(packet.protocol || "").toUpperCase();
  const flags = parseTcpFlags(packet.tcp_flags);

  if (proto === "TCP" && flags.has("SYN") && !flags.has("ACK")) {
    hints.push("Ce paquet est probablement l'étape 1 du handshake TCP.");
  }
  if (proto === "TCP" && flags.has("SYN") && flags.has("ACK")) {
    hints.push("SYN-ACK confirme que le serveur répond à une tentative d'ouverture.");
  }
  if (proto === "TCP" && flags.has("PSH") && flags.has("ACK")) {
    hints.push("PSH+ACK indique souvent des données applicatives dans une session déjà établie.");
  }
  if (isDnsPacket(packet) && proto === "UDP") {
    hints.push("DNS en UDP/53: faible overhead pour des échanges courts.");
  }
  if (isTlsPort(packet)) {
    hints.push("Le port 443 pointe vers HTTPS, donc handshake TCP puis négociation TLS.");
  }
  if ((packet.ttl_or_hop_limit ?? 255) < 40) {
    hints.push("TTL/Hop faible: le paquet a traversé plusieurs routeurs.");
  }

  if (hints.length === 0) {
    hints.push("Croise protocole, ports, flags et taille pour comprendre la phase réseau.");
  }

  return hints;
}

export function renderExplanationEmpty() {
  explanationView.innerHTML = `
    <article class="explain-card empty">
      <h3>Prêt à analyser</h3>
      <p>Sélectionne un paquet pour obtenir une explication guidée et contextualisée.</p>
    </article>
  `;
}

export function renderExplanation(packet, aiRawText = "", options = {}) {
  if (!packet) {
    renderExplanationEmpty();
    return;
  }

  const loading = Boolean(options.loading);
  const aiError = options.aiError ? String(options.aiError) : "";
  const streamText = options.streamText ? String(options.streamText) : "";
  const parsedAi = parseAiResponse(aiRawText);
  const resolvedProfile = resolveProfileMode();
  const isExpert = resolvedProfile === "expert";

  const sourcePort = packet.source_port ?? null;
  const destinationPort = packet.destination_port ?? null;
  const flowText = `${packet.source}:${formatOptional(sourcePort, "?")} -> ${packet.destination}:${formatOptional(destinationPort, "?")}`;
  const typeText = `${packet.ip_version} / ${packet.protocol}`;
  const ttlText =
    packet.ttl_or_hop_limit === null || packet.ttl_or_hop_limit === undefined
      ? "non disponible"
      : String(packet.ttl_or_hop_limit);

  const simpleSummary = [
    `Ce paquet va de ${packet.source} vers ${packet.destination}.`,
    `Type observé: ${typeText}.`,
    `Taille capturée: ${packet.length} octets.`,
    `Service probable destination: ${serviceNameForPort(destinationPort)}.`,
    `Lecture rapide flags: ${describeTcpFlags(packet.tcp_flags)}.`,
  ];

  const advancedSummary = [
    `Trajet complet: ${flowText}`,
    `EtherType: ${packet.ethertype}`,
    `TTL/Hop: ${ttlText}`,
    `Flags TCP bruts: ${formatOptional(packet.tcp_flags)}`,
    `Info parser: ${packet.info}`,
    `Hex preview: ${packet.raw_hex}`,
  ];

  const protocolList = [
    `Couche réseau (${packet.ip_version}): ${describeIpLayer(packet.ip_version)}`,
    `Couche transport (${packet.protocol}): ${describeProtocol(packet.protocol)}`,
    `Service source (${formatOptional(sourcePort, "?")}): ${serviceNameForPort(sourcePort)}`,
    `Service destination (${formatOptional(destinationPort, "?")}): ${serviceNameForPort(destinationPort)}`,
    `Sens: ${
      isPrivateIp(packet.source) && !isPrivateIp(packet.destination)
        ? "sortant (hôte local vers externe)"
        : !isPrivateIp(packet.source) && isPrivateIp(packet.destination)
          ? "entrant (externe vers hôte local)"
          : "interne/indéterminé"
    }`,
  ];

  const pedagogicList = buildLearningHints(packet);

  let aiText = parsedAi.body;
  if (loading) {
    aiText = streamText || "Génération IA en cours...";
  }
  if (aiError) {
    aiText = `Erreur IA: ${aiError}`;
  }
  if (!aiText) {
    aiText = "Réponse IA vide: lecture locale affichée ci-dessus.";
  }

  const diagnostics = parsedAi.diagnostics.length > 0 ? parsedAi.diagnostics.join("\n") : "";
  const aiSource = parsedAi.source || (loading ? "streaming" : aiError ? "fallback local" : "non précisé");
  const aiBodyHtml = renderAiBody(aiText, loading);

  explanationView.innerHTML = `
    <article class="explain-card">
      <header class="explain-header">
        <h3>Paquet #${escapeHtml(packet.id)}</h3>
        <p>${escapeHtml(packet.timestamp)} • ${escapeHtml(packet.info)}</p>
      </header>

      <section class="explain-grid">
        <div class="explain-block">
          <h4>${isExpert ? "Résumé opératoire" : "Résumé simple"}</h4>
          <ul class="explain-list">
            ${listItemsToHtml(isExpert ? advancedSummary : simpleSummary)}
          </ul>
        </div>

        <div class="explain-block">
          <h4>Lecture protocolaire</h4>
          <ul class="explain-list">
            ${listItemsToHtml(protocolList)}
          </ul>
        </div>
      </section>

      <div class="explain-block">
        <h4>Pistes pédagogiques</h4>
        <ul class="explain-list">
          ${listItemsToHtml(pedagogicList)}
        </ul>
      </div>

      <section class="explain-block explain-ai">
        <div class="explain-ai-head">
          <h4>Interprétation IA</h4>
          <span class="source-badge">Source: ${escapeHtml(aiSource)}</span>
        </div>
        <div class="ai-block ai-rich ${loading ? "is-streaming" : ""}">${aiBodyHtml}</div>
        ${diagnostics ? `<pre class="ai-block">Diagnostic: ${escapeHtml(diagnostics)}</pre>` : ""}
      </section>
    </article>
  `;
}

function renderAiBody(text, loading) {
  const lines = String(text || "")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length === 0) {
    const waiting = loading ? "Analyse en streaming..." : "Aucune donnée IA.";
    return `<p>${escapeHtml(waiting)}</p>`;
  }

  const html = [];
  let inList = false;

  const closeList = () => {
    if (inList) {
      html.push("</ul>");
      inList = false;
    }
  };

  for (const line of lines) {
    const isBullet = line.startsWith("- ") || line.startsWith("* ") || line.startsWith("• ");
    if (isBullet) {
      if (!inList) {
        html.push("<ul>");
        inList = true;
      }
      const cleaned = line.slice(2).trim();
      html.push(`<li>${escapeHtml(cleaned)}</li>`);
      continue;
    }

    closeList();
    html.push(`<p>${escapeHtml(line)}</p>`);
  }

  closeList();
  if (loading) {
    html.push('<p class="ai-stream-cursor">▌</p>');
  }

  return html.join("");
}
