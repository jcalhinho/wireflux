import { invoke } from "@tauri-apps/api/core";
import {
  aiChatClearBtn,
  aiChatCloseBtn,
  aiChatForm,
  aiChatInput,
  aiChatMessages,
  aiChatSendBtn,
  aiChatToggleBtn,
  aiChatWidget,
  state,
} from "./domState.js";
import { escapeHtml, formatOptional } from "./helpers.js";
import { t } from "./i18n.js";
import { renderMarkdownToHtml } from "./markdownLite.js";

let initialized = false;
let streamingPacketId = null;
let streamingBodyNode = null;
let pendingAsk = false;
let dragging = false;
let dragPointerId = null;
let dragOffsetX = 0;
let dragOffsetY = 0;

function hasDom() {
  return Boolean(
    aiChatWidget &&
      aiChatToggleBtn &&
      aiChatMessages &&
      aiChatCloseBtn &&
      aiChatClearBtn &&
      aiChatForm &&
      aiChatInput &&
      aiChatSendBtn,
  );
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function scrollToBottom() {
  if (!aiChatMessages) {
    return;
  }
  aiChatMessages.scrollTop = aiChatMessages.scrollHeight;
}

function setAskPending(isPending) {
  pendingAsk = Boolean(isPending);
  if (!aiChatInput || !aiChatSendBtn) {
    return;
  }

  aiChatInput.disabled = pendingAsk;
  aiChatSendBtn.disabled = pendingAsk;
}

function setToggleState(open) {
  if (!hasDom()) {
    return;
  }

  aiChatWidget.classList.toggle("hidden", !open);
  aiChatToggleBtn.setAttribute("aria-expanded", String(open));
  aiChatToggleBtn.textContent = open ? t("btn.assistant.min") : t("btn.assistant");

  if (open && !pendingAsk) {
    aiChatInput.focus({ preventScroll: true });
  }
}

function resetStreaming() {
  streamingPacketId = null;
  streamingBodyNode = null;
}

function appendMessage(kind, title, bodyHtml, metaText = "", extraClass = "") {
  if (!aiChatMessages) {
    return { body: null, item: null };
  }

  const item = document.createElement("article");
  item.className = `ai-chat-msg ai-chat-msg-${kind} ${extraClass}`.trim();

  const heading = document.createElement("strong");
  heading.className = "ai-chat-msg-title";
  heading.textContent = title;

  const body = document.createElement("div");
  body.className = "ai-chat-msg-body";
  body.innerHTML = bodyHtml;

  item.appendChild(heading);
  item.appendChild(body);

  if (metaText) {
    const meta = document.createElement("small");
    meta.className = "ai-chat-meta";
    meta.textContent = metaText;
    item.appendChild(meta);
  }

  aiChatMessages.appendChild(item);
  scrollToBottom();
  return { body, item };
}

function renderEmptyState() {
  if (!aiChatMessages || !aiChatInput) {
    return;
  }

  aiChatMessages.innerHTML =
    `<div class="ai-chat-empty">${escapeHtml(t("ai.empty"))}</div>`;
  aiChatInput.value = "";
  setAskPending(false);
  resetStreaming();
}

function packetSummaryLine(packet) {
  return `${packet.source}:${formatOptional(packet.source_port, "?")} -> ${packet.destination}:${formatOptional(packet.destination_port, "?")}`;
}

function renderPacketContext(packet, model) {
  if (!aiChatMessages) {
    return;
  }

  aiChatMessages.innerHTML = "";
  appendMessage(
    "user",
    `Paquet #${packet.id}`,
    `<p>${escapeHtml(packetSummaryLine(packet))}</p><p>${escapeHtml(packet.ip_version)} / ${escapeHtml(packet.protocol)}</p>`,
    `Modele: ${model || "non selectionne"}`,
  );
}

function getSelectedPacket() {
  if (!state.selectedPacketId) {
    return null;
  }
  return state.packets.find((packet) => packet.id === state.selectedPacketId) || null;
}

async function submitQuestion() {
  if (!hasDom() || pendingAsk) {
    return;
  }

  const question = String(aiChatInput.value || "").trim();
  if (!question) {
    aiChatInput.focus({ preventScroll: true });
    return;
  }

  openFloatingAiChat();

  const selectedPacket = getSelectedPacket();
  const packetHint = selectedPacket
    ? t("meta.packet.context", { id: selectedPacket.id, protocol: selectedPacket.protocol })
    : t("meta.packet.none");

  appendMessage("user", t("ai.question"), `<p>${escapeHtml(question)}</p>`, packetHint);
  aiChatInput.value = "";

  const pending = appendMessage(
    "assistant",
    t("ai.answer"),
    `<p>${escapeHtml(t("ai.generating"))}</p>`,
    t("ai.model", { model: state.selectedModel || "auto" }),
    "is-streaming",
  );

  setAskPending(true);

  try {
    const answer = await invoke("ask_ai_question", {
      question,
      model: state.selectedModel,
      packet: selectedPacket,
      lang: state.lang ?? "fr",
    });

    if (pending.item) {
      pending.item.classList.remove("is-streaming");
    }
    if (pending.body) {
      const rendered = renderMarkdownToHtml(String(answer || "").trim() || t("ai.response.empty"));
      pending.body.innerHTML = rendered;
    }
    scrollToBottom();
  } catch (error) {
    const safeError = escapeHtml(String(error || t("ai.error.generic")));
    if (pending.item) {
      pending.item.classList.remove("is-streaming");
      pending.item.classList.add("is-error");
    }
    if (pending.body) {
      pending.body.innerHTML = `<p>${safeError}</p>`;
    }
  } finally {
    setAskPending(false);
    aiChatInput.focus({ preventScroll: true });
  }
}

function startDragging(event) {
  if (!aiChatWidget || !hasDom()) {
    return;
  }

  const isMouse = event.pointerType === "mouse";
  if ((isMouse && event.button !== 0) || event.target.closest("button")) {
    return;
  }

  const rect = aiChatWidget.getBoundingClientRect();
  aiChatWidget.style.left = `${rect.left}px`;
  aiChatWidget.style.top = `${rect.top}px`;
  aiChatWidget.style.right = "auto";
  aiChatWidget.style.bottom = "auto";

  dragging = true;
  dragPointerId = event.pointerId;
  dragOffsetX = event.clientX - rect.left;
  dragOffsetY = event.clientY - rect.top;

  const head = aiChatWidget.querySelector(".ai-chat-head");
  head?.setPointerCapture?.(event.pointerId);
  aiChatWidget.classList.add("is-dragging");
  event.preventDefault();
}

function moveDragging(event) {
  if (!dragging || event.pointerId !== dragPointerId || !aiChatWidget) {
    return;
  }

  const margin = 8;
  const maxLeft = window.innerWidth - aiChatWidget.offsetWidth - margin;
  const maxTop = window.innerHeight - aiChatWidget.offsetHeight - margin;

  const nextLeft = clamp(event.clientX - dragOffsetX, margin, Math.max(margin, maxLeft));
  const nextTop = clamp(event.clientY - dragOffsetY, margin, Math.max(margin, maxTop));

  aiChatWidget.style.left = `${nextLeft}px`;
  aiChatWidget.style.top = `${nextTop}px`;
}

function stopDragging(event) {
  if (!dragging || event.pointerId !== dragPointerId || !aiChatWidget) {
    return;
  }

  dragging = false;
  dragPointerId = null;
  aiChatWidget.classList.remove("is-dragging");

  const head = aiChatWidget.querySelector(".ai-chat-head");
  head?.releasePointerCapture?.(event.pointerId);
}

function clampWidgetOnResize() {
  if (!aiChatWidget || !aiChatWidget.style.left || !aiChatWidget.style.top) {
    return;
  }

  const margin = 8;
  const maxLeft = window.innerWidth - aiChatWidget.offsetWidth - margin;
  const maxTop = window.innerHeight - aiChatWidget.offsetHeight - margin;

  const currentLeft = Number.parseFloat(aiChatWidget.style.left || "0");
  const currentTop = Number.parseFloat(aiChatWidget.style.top || "0");

  aiChatWidget.style.left = `${clamp(currentLeft, margin, Math.max(margin, maxLeft))}px`;
  aiChatWidget.style.top = `${clamp(currentTop, margin, Math.max(margin, maxTop))}px`;
}

function bindResizeObserver() {
  if (!aiChatWidget || typeof ResizeObserver !== "function") {
    return;
  }

  const observer = new ResizeObserver(() => {
    clampWidgetOnResize();
  });
  observer.observe(aiChatWidget);
}

function bindDragging() {
  if (!aiChatWidget) {
    return;
  }

  const head = aiChatWidget.querySelector(".ai-chat-head");
  if (!head) {
    return;
  }

  head.addEventListener("pointerdown", startDragging);
  head.addEventListener("pointermove", moveDragging);
  head.addEventListener("pointerup", stopDragging);
  head.addEventListener("pointercancel", stopDragging);
  window.addEventListener("resize", clampWidgetOnResize);
}

export function initFloatingAiChat() {
  if (!hasDom() || initialized) {
    return;
  }
  initialized = true;

  setToggleState(false);
  renderEmptyState();
  bindDragging();
  bindResizeObserver();

  aiChatToggleBtn.addEventListener("click", () => {
    const isOpen = aiChatToggleBtn.getAttribute("aria-expanded") === "true";
    setToggleState(!isOpen);
  });

  aiChatCloseBtn.addEventListener("click", () => {
    setToggleState(false);
  });

  aiChatClearBtn.addEventListener("click", () => {
    renderEmptyState();
  });

  aiChatForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void submitQuestion();
  });
}

export function openFloatingAiChat() {
  setToggleState(true);
}

export function closeFloatingAiChat() {
  setToggleState(false);
}

export function resetFloatingAiChat() {
  if (!hasDom()) {
    return;
  }
  renderEmptyState();
}

export function showAiChatLoading(packet, model) {
  if (!hasDom() || !packet) {
    return;
  }

  openFloatingAiChat();
  renderPacketContext(packet, model);
  const created = appendMessage(
    "assistant",
    t("ai.analysis"),
    `<p>${escapeHtml(t("ai.loading"))}</p>`,
    t("ai.streaming"),
    "is-streaming",
  );

  streamingPacketId = packet.id;
  streamingBodyNode = created.body;
}

export function updateAiChatStream(packetId, streamText) {
  if (!streamingBodyNode || streamingPacketId !== packetId) {
    return;
  }

  const safeText = String(streamText || "").trim();
  const rendered = renderMarkdownToHtml(safeText || t("ai.loading"), { loading: true });
  streamingBodyNode.innerHTML = rendered;
  scrollToBottom();
}

export function showAiChatResult(packet, aiText, model) {
  if (!hasDom() || !packet) {
    return;
  }

  openFloatingAiChat();
  renderPacketContext(packet, model);

  const body = String(aiText || "").trim();
  const rendered = renderMarkdownToHtml(body || t("ai.response.empty.local"));
  appendMessage("assistant", t("ai.analysis"), rendered, t("ai.source", { source: model || "fallback" }));

  resetStreaming();
}

export function showAiChatError(packet, errorText, model) {
  if (!hasDom() || !packet) {
    return;
  }

  openFloatingAiChat();
  renderPacketContext(packet, model);

  const safeError = escapeHtml(String(errorText || t("ai.error.generic")));
  appendMessage(
    "assistant",
    t("ai.analysis"),
    `<p>${safeError}</p>`,
    t("ai.source", { source: t("ai.source.fallback") }),
    "is-error",
  );

  resetStreaming();
}
