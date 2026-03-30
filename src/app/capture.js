import { invoke } from "@tauri-apps/api/core";
import {
  MAX_STORED_PACKETS,
  conversationKeyForPacket,
  interfaceGuideText,
  interfaceMetaText,
  interfaceSelect,
  modelSelect,
  setAiStatus,
  setCaptureButtons,
  setStatus,
  state,
} from "./domState.js";
import { aiCacheKey } from "./domState.js";
import { analyzePacketForAlerts, resetAlertState } from "./alerts.js";
import { ensureChartsLoaded, resetTrafficState, startGraphTicker, stopGraphTicker } from "./charts.js";
import { renderExplanation, renderExplanationEmpty } from "./explainCoach.js";
import {
  openFloatingAiChat,
  resetFloatingAiChat,
  showAiChatError,
  showAiChatLoading,
  showAiChatResult,
  updateAiChatStream,
} from "./floatingAiChat.js";
import { renderHandshakeDecoder } from "./handshakeView.js";
import { t } from "./i18n.js";
import { ensureConversation } from "./storyFlow.js";
import { findPacketById, renderPageControls, renderTablePage } from "./tableView.js";

function inferInterfaceKindKey(name, description = "", kind = "") {
  const normalized = `${String(name || "").toLowerCase()} ${String(description || "").toLowerCase()} ${String(kind || "").toLowerCase()}`;
  if (!normalized) {
    return "default";
  }
  if (normalized.includes("loopback") || normalized.startsWith("lo")) {
    return "loopback";
  }
  if (
    normalized.includes("wifi") ||
    normalized.includes("wi-fi") ||
    normalized.includes("wlan") ||
    normalized.includes("airport")
  ) {
    return "wifi";
  }
  if (normalized.startsWith("eth") || normalized.startsWith("en")) {
    return "ethernet";
  }
  if (
    normalized.includes("vpn") ||
    normalized.includes("utun") ||
    normalized.includes("tun") ||
    normalized.includes("tap")
  ) {
    return "vpn";
  }
  if (normalized.includes("docker") || normalized.includes("vmnet") || normalized.includes("bridge")) {
    return "virtual";
  }
  return "default";
}

function interfaceKindLabel(kindKey) {
  switch (kindKey) {
    case "loopback":
      return t("interface.kind.loopback");
    case "wifi":
      return t("interface.kind.wifi");
    case "ethernet":
      return t("interface.kind.ethernet");
    case "vpn":
      return t("interface.kind.vpn");
    case "virtual":
      return t("interface.kind.virtual");
    default:
      return t("interface.kind.default");
  }
}

function normalizeInterfaceDetails(payload) {
  if (!Array.isArray(payload)) {
    return [];
  }

  const normalized = [];
  for (const item of payload) {
    if (!item) {
      continue;
    }

    if (typeof item === "string") {
      const name = String(item);
      normalized.push({
        name,
        displayName: name,
        kindKey: inferInterfaceKindKey(name),
        description: "",
        osiHint: "",
        macAddress: "",
      });
      continue;
    }

    const name = String(item.name || "").trim();
    if (!name) {
      continue;
    }
    const description = String(item.description || "").trim();
    const kind = String(item.kind || "").trim();
    const kindKey = inferInterfaceKindKey(name, description, kind);
    const displayName = String(item.display_name || "").trim() || (description ? `${name} — ${description}` : name);
    const osiHint = String(item.osi_hint || "").trim() || "";
    const macAddress = String(item.mac_address || "").trim();

    normalized.push({
      name,
      displayName,
      kind,
      kindKey,
      description,
      osiHint,
      macAddress,
    });
  }

  return normalized;
}

export function updateInterfaceEducation() {
  if (!interfaceGuideText || !interfaceMetaText || !interfaceSelect) {
    return;
  }

  const selected = String(interfaceSelect.value || "").trim();
  if (!selected) {
    interfaceGuideText.textContent = t("interface.guide.default");
    interfaceMetaText.textContent = t("interface.none.selected");
    return;
  }

  const details = state.interfaceDetails.get(selected);
  if (!details) {
    const inferredKind = interfaceKindLabel(inferInterfaceKindKey(selected));
    interfaceGuideText.textContent = t("interface.guide.stack", { kind: inferredKind });
    interfaceMetaText.textContent = t("interface.meta.fallback", { name: selected, kind: inferredKind });
    return;
  }

  const kindLabel = interfaceKindLabel(details.kindKey || inferInterfaceKindKey(details.name, details.description, details.kind));
  interfaceGuideText.textContent = t("interface.guide.stack", { kind: kindLabel });
  const descriptionText = details.description ? ` | ${t("interface.meta.detail")}: ${details.description}` : "";
  const macText = details.macAddress ? ` | MAC: ${details.macAddress}` : "";
  interfaceMetaText.textContent = t("interface.meta.fallback", { name: details.name, kind: kindLabel }) + descriptionText + macText;
}

function setModelOptions(models, selectedFromStatus, requiresSelection) {
  modelSelect.innerHTML = "";
  state.selectedModel = null;

  if (!Array.isArray(models) || models.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = t("model.none");
    modelSelect.appendChild(option);
    modelSelect.disabled = true;
    return;
  }

  if (requiresSelection) {
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = t("model.choose");
    modelSelect.appendChild(placeholder);
    modelSelect.value = "";
  }

  for (const modelName of models) {
    const option = document.createElement("option");
    option.value = modelName;
    option.textContent = modelName;
    modelSelect.appendChild(option);
  }

  if (selectedFromStatus && models.includes(selectedFromStatus)) {
    modelSelect.value = selectedFromStatus;
    state.selectedModel = selectedFromStatus;
  } else if (!requiresSelection && models.length > 0) {
    modelSelect.value = models[0];
    state.selectedModel = models[0];
  }

  modelSelect.disabled = false;
}

export async function refreshAiStatus() {
  try {
    const status = await invoke("ai_status");
    if (!status || typeof status !== "object") {
      setAiStatus(t("status.ai.invalid"), true);
      setModelOptions([], null, false);
      return;
    }

    const stateValue = String(status.state ?? "");
    const message = String(status.message ?? "");
    const models = Array.isArray(status.models) ? status.models : [];
    const selectedFromStatus = typeof status.selected_model === "string" ? status.selected_model : null;
    const requiresSelection = Boolean(status.requires_selection);

    setModelOptions(models, selectedFromStatus, requiresSelection);

    if (stateValue === "ready") {
      setAiStatus(message || t("status.ai.connected.model", { model: state.selectedModel || "auto" }));
      return;
    }
    if (stateValue === "needs_selection") {
      setAiStatus(message || t("status.model.required"), true);
      return;
    }

    setAiStatus(message || t("status.ai.unavailable"), true);
  } catch (error) {
    setAiStatus(t("status.ai.check.error", { error: String(error) }), true);
    setModelOptions([], null, false);
  }
}

function resetSessionViews() {
  state.packets = [];
  state.packetMap = new Map();
  state.droppedPackets = 0;
  state.currentPage = 1;
  state.selectedPacketId = null;
  state.selectedConversationKey = null;
  state.conversations = new Map();
  state.aiCache = new Map();
  state.aiErrorCache = new Map();
  state.aiStreamRequestId = null;
  state.aiStreamBuffer = "";

  renderTablePage();
  renderExplanationEmpty();
  renderHandshakeDecoder();
  resetFloatingAiChat();
}

let lastSecondaryRenderAt = 0;
const SECONDARY_RENDER_INTERVAL_MS = 300;

function appendPackets(batch) {
  let batchBytes = 0;
  const previousPacketCount = state.packets.length;

  for (const packet of batch) {
    state.packets.push(packet);
    state.packetMap.set(packet.id, packet);
    batchBytes += packet.length ?? 0;

    ensureConversation(packet);
    analyzePacketForAlerts(packet);
  }

  if (state.packets.length > MAX_STORED_PACKETS) {
    const overflow = state.packets.length - MAX_STORED_PACKETS;
    for (let i = 0; i < overflow; i++) {
      state.packetMap.delete(state.packets[i].id);
    }
    state.packets = state.packets.slice(overflow);
    state.droppedPackets += overflow;
  }

  state.currentSecondPackets += batch.length;
  state.currentSecondBytes += batchBytes;
  state.totalPackets += batch.length;

  const firstPageCanChange = previousPacketCount < state.pageSize;
  if (state.currentPage !== 1 || firstPageCanChange) {
    renderTablePage();
  } else {
    renderPageControls();
  }

  const now = Date.now();
  if (now - lastSecondaryRenderAt >= SECONDARY_RENDER_INTERVAL_MS) {
    lastSecondaryRenderAt = now;
    renderHandshakeDecoder();
  }
}

export async function loadInterfaces() {
  const previousSelection = interfaceSelect.value;
  interfaceSelect.innerHTML = "";
  state.interfaceDetails = new Map();

  try {
    let interfaces = [];
    try {
      const detailsPayload = await invoke("list_interfaces_details");
      interfaces = normalizeInterfaceDetails(detailsPayload);
    } catch {
      const names = await invoke("list_interfaces");
      interfaces = normalizeInterfaceDetails(names);
    }

    for (const details of interfaces) {
      const option = document.createElement("option");
      option.value = details.name;
      option.textContent = details.displayName || details.name;
      interfaceSelect.appendChild(option);
      state.interfaceDetails.set(details.name, details);
    }

    if (previousSelection && state.interfaceDetails.has(previousSelection)) {
      interfaceSelect.value = previousSelection;
    }

    if (interfaces.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = t("interface.none");
      interfaceSelect.appendChild(option);
    }

    updateInterfaceEducation();
  } catch (error) {
    setStatus("error", `interfaces: ${String(error)}`);
    updateInterfaceEducation();
  }
}

export async function selectPacket(packet) {
  state.selectedPacketId = packet.id;
  state.selectedConversationKey = conversationKeyForPacket(packet);
  state.aiStreamRequestId = null;
  state.aiStreamBuffer = "";

  renderTablePage();
  renderHandshakeDecoder();
  renderExplanation(packet);
  openFloatingAiChat();

  if (!state.selectedModel) {
    setAiStatus(t("status.model.required"), true);
    showAiChatError(packet, t("status.model.required"), state.selectedModel);
    renderExplanation(packet, "", {
      aiError: t("status.model.required"),
    });
    return;
  }

  const cacheKey = aiCacheKey(packet.id, state.selectedModel);
  const cachedAi = state.aiCache.get(cacheKey);
  const cachedError = state.aiErrorCache.get(cacheKey);

  if (cachedAi || cachedError) {
    if (cachedError) {
      showAiChatError(packet, cachedError, state.selectedModel);
    } else {
      showAiChatResult(packet, cachedAi, state.selectedModel);
    }
    return;
  }

  const requestId = `${packet.id}-${Date.now()}`;
  state.aiStreamRequestId = requestId;
  state.aiStreamBuffer = "";
  showAiChatLoading(packet, state.selectedModel);
  setAiStatus(t("status.ai.stream", { model: state.selectedModel }));

  try {
    await invoke("explain_packet_stream", {
      packet,
      model: state.selectedModel,
      requestId,
      lang: state.lang ?? "fr",
    });
  } catch (error) {
    state.aiErrorCache.set(cacheKey, String(error));
    if (state.selectedPacketId === packet.id) {
      showAiChatError(packet, String(error), state.selectedModel);
    }
    setAiStatus(t("status.ai.backend.error"), true);
    await refreshAiStatus();
  }
}

export async function startCapture() {
  const iface = interfaceSelect.value;
  if (!iface) {
    setStatus("error", t("status.interface.required"));
    return;
  }

  resetSessionViews();
  resetTrafficState();
  resetAlertState();
  setAiStatus(t("status.connecting"));

  try {
    await ensureChartsLoaded();
    await invoke("start_capture", { interface: iface });
    state.isCaptureRunning = true;
    setCaptureButtons(true);
    startGraphTicker();
    await refreshAiStatus();
  } catch (error) {
    const message = String(error || "");
    const normalized = message.toLowerCase();
    if (
      normalized.includes("déjà en cours") ||
      normalized.includes("deja en cours") ||
      normalized.includes("already running")
    ) {
      try {
        await invoke("stop_capture");
        await invoke("start_capture", { interface: iface });
        state.isCaptureRunning = true;
        setCaptureButtons(true);
        startGraphTicker();
        setStatus("running", t("status.capture.resynced"));
        await refreshAiStatus();
        return;
      } catch (restartError) {
        setStatus("error", String(restartError));
      }
    } else {
      setStatus("error", message);
    }

    state.isCaptureRunning = false;
    setCaptureButtons(false);
    stopGraphTicker();
  }
}

export async function stopCapture() {
  state.isCaptureRunning = false;
  setCaptureButtons(false);
  stopGraphTicker();

  try {
    await invoke("stop_capture");
  } catch (error) {
    setStatus("error", String(error));
  }
}

export async function handleCaptureStatus(payload) {
  if (payload.state === "running") {
    const currentInterface = interfaceSelect?.value || "?";
    setStatus(payload.state, t("status.capture.running", { interface: currentInterface }));
  } else if (payload.state === "idle" || payload.state === "stopping") {
    setStatus(payload.state, "");
  } else {
    setStatus(payload.state, payload.message);
  }

  if (payload.state === "running") {
    state.isCaptureRunning = true;
    setCaptureButtons(true);
    startGraphTicker();
  }

  if (payload.state === "idle" || payload.state === "error") {
    state.isCaptureRunning = false;
    setCaptureButtons(false);
    stopGraphTicker();
  }
}

export function handlePacketBatch(batch) {
  if (Array.isArray(batch) && batch.length > 0) {
    appendPackets(batch);
  }
}

export function reselectCurrentPacket() {
  if (!state.selectedPacketId) {
    return;
  }
  const packet = findPacketById(state.selectedPacketId);
  if (packet) {
    void selectPacket(packet);
  }
}

function isExpectedStreamPayload(payload) {
  return payload && typeof payload === "object" && typeof payload.request_id === "string";
}

export function handleAiStreamChunk(payload) {
  if (!isExpectedStreamPayload(payload)) {
    return;
  }

  if (payload.request_id !== state.aiStreamRequestId) {
    return;
  }

  state.aiStreamBuffer += String(payload.chunk || "");
  if (!state.selectedPacketId) {
    return;
  }

  const packet = findPacketById(state.selectedPacketId);
  if (!packet) {
    return;
  }

  updateAiChatStream(packet.id, state.aiStreamBuffer);
}

export function handleAiStreamDone(payload) {
  if (!isExpectedStreamPayload(payload)) {
    return;
  }

  if (payload.request_id !== state.aiStreamRequestId) {
    return;
  }

  if (!state.selectedPacketId) {
    state.aiStreamRequestId = null;
    state.aiStreamBuffer = "";
    return;
  }

  const packet = findPacketById(state.selectedPacketId);
  if (!packet) {
    state.aiStreamRequestId = null;
    state.aiStreamBuffer = "";
    return;
  }

  const aiText = String(payload.text || "").trim();
  const cacheKey = aiCacheKey(packet.id, state.selectedModel);
  state.aiCache.set(cacheKey, aiText);
  state.aiErrorCache.delete(cacheKey);
  state.aiStreamRequestId = null;
  state.aiStreamBuffer = "";

  showAiChatResult(packet, aiText, state.selectedModel);
  setAiStatus(t("status.ai.connected.model", { model: state.selectedModel }));
}

export async function handleAiStreamError(payload) {
  if (!isExpectedStreamPayload(payload)) {
    return;
  }

  if (payload.request_id !== state.aiStreamRequestId) {
    return;
  }

  const message = String(payload.message || t("status.stream.interrupted"));
  state.aiStreamRequestId = null;
  state.aiStreamBuffer = "";

  if (state.selectedPacketId) {
    const packet = findPacketById(state.selectedPacketId);
    if (packet) {
      const cacheKey = aiCacheKey(packet.id, state.selectedModel);
      state.aiErrorCache.set(cacheKey, message);
      showAiChatError(packet, message, state.selectedModel);
    }
  }

  setAiStatus(message, true);
  await refreshAiStatus();
}
