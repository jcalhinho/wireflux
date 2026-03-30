import {
  aiCacheKey,
  coachView,
  explanationView,
  resolveProfileMode,
  state,
  updateProfileStatus,
} from "./domState.js";
import {
  detectLayerHeuristics,
  describeIpLayer,
  describeProtocol,
  describeTcpFlags,
  escapeHtml,
  formatOptional,
  isDnsPacket,
  isPrivateIp,
  isTlsPort,
  listItemsToHtml,
  parseTcpFlags,
  serviceNameForPort,
} from "./helpers.js";
import { t } from "./i18n.js";

let findPacketById = () => null;

export function setExplainHooks(hooks) {
  findPacketById = hooks?.findPacketById || findPacketById;
}

function createQuizForPacket(packet) {
  const proto = String(packet.protocol || "").toUpperCase();
  const flags = parseTcpFlags(packet.tcp_flags);

  if (proto === "TCP" && flags.has("SYN") && !flags.has("ACK")) {
    return {
      questionKey: "quiz.syn.question",
      options: [
        { textKey: "quiz.syn.opt.open", correct: true },
        { textKey: "quiz.syn.opt.close", correct: false },
        { textKey: "quiz.syn.opt.icmp", correct: false },
      ],
      explanationKey: "quiz.syn.explanation",
    };
  }

  if (proto === "TCP" && flags.has("SYN") && flags.has("ACK")) {
    return {
      questionKey: "quiz.synack.question",
      options: [
        { textKey: "quiz.synack.opt.server", correct: true },
        { textKey: "quiz.synack.opt.tls", correct: false },
        { textKey: "quiz.synack.opt.fin", correct: false },
      ],
      explanationKey: "quiz.synack.explanation",
    };
  }

  if (proto === "TCP" && flags.has("PSH") && flags.has("ACK")) {
    return {
      questionKey: "quiz.pshack.question",
      options: [
        { textKey: "quiz.pshack.opt.data", correct: true },
        { textKey: "quiz.pshack.opt.dns", correct: false },
        { textKey: "quiz.pshack.opt.arp", correct: false },
      ],
      explanationKey: "quiz.pshack.explanation",
    };
  }

  if (proto === "UDP" && (packet.destination_port === 53 || packet.source_port === 53)) {
    return {
      questionKey: "quiz.dns.question",
      options: [
        { textKey: "quiz.dns.opt.latency", correct: true },
        { textKey: "quiz.dns.opt.encrypt", correct: false },
        { textKey: "quiz.dns.opt.order", correct: false },
      ],
      explanationKey: "quiz.dns.explanation",
    };
  }

  if (packet.destination_port === 443 || packet.source_port === 443) {
    return {
      questionKey: "quiz.443.question",
      options: [
        { textKey: "quiz.443.opt.https", correct: true },
        { textKey: "quiz.443.opt.ssh", correct: false },
        { textKey: "quiz.443.opt.smtp", correct: false },
      ],
      explanationKey: "quiz.443.explanation",
    };
  }

  if (proto === "ICMP" || proto === "ICMPV6") {
    return {
      questionKey: "quiz.icmp.question",
      options: [
        { textKey: "quiz.icmp.opt.diagnostic", correct: true },
        { textKey: "quiz.icmp.opt.web", correct: false },
        { textKey: "quiz.icmp.opt.tls", correct: false },
      ],
      explanationKey: "quiz.icmp.explanation",
    };
  }

  return {
    questionKey: "quiz.default.question",
    options: [
      { textKey: "quiz.default.opt.infer", correct: true },
      { textKey: "quiz.default.opt.password", correct: false },
      { textKey: "quiz.default.opt.noinspect", correct: false },
    ],
    explanationKey: "quiz.default.explanation",
  };
}

export function renderCoach() {
  if (!coachView) {
    return;
  }
  coachView.innerHTML = "";

  if (!state.coach.quiz) {
    coachView.innerHTML = `<div class="coach-empty">${escapeHtml(t("coach.empty"))}</div>`;
    return;
  }

  const wrapper = document.createElement("article");
  wrapper.className = "coach-card";

  const title = document.createElement("h3");
  title.textContent = t("coach.title");

  const question = document.createElement("p");
  question.className = "coach-question";
  question.textContent = t(state.coach.quiz.questionKey);

  const options = document.createElement("div");
  options.className = "coach-options";

  state.coach.quiz.options.forEach((option, index) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "coach-option";
    btn.textContent = t(option.textKey);

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
  score.textContent = t("coach.score", { correct: state.quizCorrect, total: state.quizAnswered });

  footer.appendChild(score);

  if (state.coach.answered) {
    const explain = document.createElement("p");
    explain.className = "coach-explain";
    explain.textContent = t(state.coach.quiz.explanationKey);
    footer.appendChild(explain);
  }

  wrapper.appendChild(title);
  wrapper.appendChild(question);
  wrapper.appendChild(options);
  wrapper.appendChild(footer);

  coachView.appendChild(wrapper);
}

export function prepareCoach(packet) {
  if (!coachView) {
    return;
  }
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
    hints.push(t("hint.syn"));
  }
  if (proto === "TCP" && flags.has("SYN") && flags.has("ACK")) {
    hints.push(t("hint.synack"));
  }
  if (proto === "TCP" && flags.has("PSH") && flags.has("ACK")) {
    hints.push(t("hint.pshack"));
  }
  if (isDnsPacket(packet) && proto === "UDP") {
    hints.push(t("hint.dns"));
  }
  if (isTlsPort(packet)) {
    hints.push(t("hint.tls"));
  }
  if ((packet.ttl_or_hop_limit ?? 255) < 40) {
    hints.push(t("hint.ttl"));
  }

  if (hints.length === 0) {
    hints.push(t("hint.default"));
  }

  return hints;
}

export function renderExplanationEmpty() {
  explanationView.innerHTML = `
    <article class="explain-card empty">
      <h3>${escapeHtml(t("explain.ready.title"))}</h3>
      <p>${escapeHtml(t("explain.ready.desc"))}</p>
    </article>
  `;
}

export function renderExplanation(packet, _aiRawText = "", _options = {}) {
  if (!packet) {
    renderExplanationEmpty();
    return;
  }

  const resolvedProfile = resolveProfileMode();
  const isExpert = resolvedProfile === "expert";

  const sourcePort = packet.source_port ?? null;
  const destinationPort = packet.destination_port ?? null;
  const flowText = `${packet.source}:${formatOptional(sourcePort, "?")} -> ${packet.destination}:${formatOptional(destinationPort, "?")}`;
  const typeText = `${packet.ip_version} / ${packet.protocol}`;
  const ttlText =
    packet.ttl_or_hop_limit === null || packet.ttl_or_hop_limit === undefined
      ? t("table.tip.unavailable")
      : String(packet.ttl_or_hop_limit);

  const simpleSummary = [
    t("explain.summary.flow", { source: packet.source, destination: packet.destination }),
    t("explain.summary.type", { type: typeText }),
    t("explain.summary.size", { size: packet.length, unit: t("size.b") }),
    t("explain.summary.service", { service: serviceNameForPort(destinationPort) }),
    t("explain.summary.flags", { flags: describeTcpFlags(packet.tcp_flags) }),
  ];

  const advancedSummary = [
    t("explain.advanced.path", { flow: flowText }),
    `EtherType: ${packet.ethertype}`,
    `TTL/Hop: ${ttlText}`,
    t("explain.advanced.tcp.flags", { flags: formatOptional(packet.tcp_flags) }),
    t("explain.advanced.info", { info: packet.info }),
    `Hex preview: ${packet.raw_hex}`,
  ];

  const protocolList = [
    t("explain.protocol.network", { version: packet.ip_version, desc: describeIpLayer(packet.ip_version) }),
    t("explain.protocol.transport", { protocol: packet.protocol, desc: describeProtocol(packet.protocol) }),
    t("explain.protocol.source", { port: formatOptional(sourcePort, "?"), service: serviceNameForPort(sourcePort) }),
    t("explain.protocol.destination", {
      port: formatOptional(destinationPort, "?"),
      service: serviceNameForPort(destinationPort),
    }),
    `${t("explain.protocol.direction")}: ${
      isPrivateIp(packet.source) && !isPrivateIp(packet.destination)
        ? t("explain.direction.outbound")
        : !isPrivateIp(packet.source) && isPrivateIp(packet.destination)
          ? t("explain.direction.inbound")
          : t("explain.direction.internal")
    }`,
  ];
  const layerHeuristics = detectLayerHeuristics(packet);
  const l6Reasons = layerHeuristics.presentation.reasons.length
    ? layerHeuristics.presentation.reasons.join("; ")
    : t("explain.no.strong.signal");
  const l5Reasons = layerHeuristics.session.reasons.length
    ? layerHeuristics.session.reasons.join("; ")
    : t("explain.no.strong.signal");
  const heuristicList = [
    `${t("explain.heuristic.l6")}: ${
      layerHeuristics.presentation.matched
        ? `${t("table.tip.detected")} (${t("explain.confidence")} ${layerHeuristics.presentation.confidence})`
        : t("table.tip.not.detected")
    }`,
    `${t("explain.heuristic.l6.signals")}: ${l6Reasons}`,
    `${t("explain.heuristic.l6.false")}: ${layerHeuristics.presentation.falsePositiveRisk} — ${layerHeuristics.presentation.falsePositiveNote}`,
    `${t("explain.heuristic.l5")}: ${
      layerHeuristics.session.matched
        ? `${t("table.tip.detected")} (${t("explain.confidence")} ${layerHeuristics.session.confidence})`
        : t("table.tip.not.detected")
    }`,
    `${t("explain.heuristic.l5.signals")}: ${l5Reasons}`,
    `${t("explain.heuristic.l5.false")}: ${layerHeuristics.session.falsePositiveRisk} — ${layerHeuristics.session.falsePositiveNote}`,
  ];

  const pedagogicList = buildLearningHints(packet);

  explanationView.innerHTML = `
    <article class="explain-card explain-card-simple">
      <header class="explain-header">
        <h3>${escapeHtml(t("explain.packet", { id: packet.id }))}</h3>
        <p>${escapeHtml(packet.timestamp)} • ${escapeHtml(packet.info)}</p>
      </header>

      <section class="explain-grid">
        <div class="explain-block">
          <h4>${isExpert ? escapeHtml(t("explain.summary.operational")) : escapeHtml(t("explain.summary.simple"))}</h4>
          <ul class="explain-list">
            ${listItemsToHtml(isExpert ? advancedSummary : simpleSummary)}
          </ul>
        </div>

        <div class="explain-block">
          <h4>${escapeHtml(t("explain.protocol.reading"))}</h4>
          <ul class="explain-list">
            ${listItemsToHtml(protocolList)}
          </ul>
        </div>
      </section>

      <div class="explain-block">
        <h4>${escapeHtml(t("explain.hints"))}</h4>
        <ul class="explain-list">
          ${listItemsToHtml(pedagogicList)}
        </ul>
      </div>

      <div class="explain-block">
        <h4>${escapeHtml(t("explain.heuristic.title"))}</h4>
        <ul class="explain-list">
          ${listItemsToHtml(heuristicList)}
        </ul>
      </div>

      <p class="oracle-subtext">
        ${escapeHtml(t("explain.ai.subtext.before"))}
        <strong>${escapeHtml(t("btn.assistant"))}</strong>
        ${escapeHtml(t("explain.ai.subtext.after"))}
      </p>
    </article>
  `;
}
