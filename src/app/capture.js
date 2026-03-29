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
import { ensureConversation, processStoryEvent, renderFlowMap, renderStoryList } from "./storyFlow.js";
import { findPacketById, renderPageControls, renderTablePage } from "./tableView.js";

function inferInterfaceKind(name) {
  const normalized = String(name || "").toLowerCase();
  if (!normalized) {
    return "Interface réseau";
  }
  if (normalized === "lo" || normalized.startsWith("lo")) {
    return "Boucle locale (loopback)";
  }
  if (
    normalized.includes("wifi") ||
    normalized.includes("wlan") ||
    normalized.includes("airport")
  ) {
    return "Interface Wi-Fi";
  }
  if (normalized.startsWith("eth") || normalized.startsWith("en")) {
    return "Interface Ethernet";
  }
  if (
    normalized.includes("vpn") ||
    normalized.includes("utun") ||
    normalized.includes("tun") ||
    normalized.includes("tap")
  ) {
    return "Tunnel / VPN";
  }
  if (normalized.includes("docker") || normalized.includes("vmnet") || normalized.includes("bridge")) {
    return "Interface virtuelle / bridge";
  }
  return "Interface réseau";
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
        kind: inferInterfaceKind(name),
        description: "",
        osiHint: "Point d'entree couche 1 (materiel), puis couche 2 (trames).",
        macAddress: "",
      });
      continue;
    }

    const name = String(item.name || "").trim();
    if (!name) {
      continue;
    }
    const description = String(item.description || "").trim();
    const kind = String(item.kind || "").trim() || inferInterfaceKind(name);
    const displayName = String(item.display_name || "").trim() || (description ? `${name} — ${description}` : name);
    const osiHint =
      String(item.osi_hint || "").trim() ||
      `${kind}: point d'entree couche 1 (materiel) puis couche 2 (trame Ethernet/Wi-Fi).`;
    const macAddress = String(item.mac_address || "").trim();

    normalized.push({
      name,
      displayName,
      kind,
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
    interfaceGuideText.textContent =
      "Choisis l'interface materielle a ecouter: c'est le point de depart couche 1, avant toute analyse L2/L3/L4/L7.";
    interfaceMetaText.textContent = "Aucune interface selectionnee.";
    return;
  }

  const details = state.interfaceDetails.get(selected);
  if (!details) {
    const inferredKind = inferInterfaceKind(selected);
    interfaceGuideText.textContent = `${inferredKind}: la capture part de la couche 1 puis remonte la pile protocolaire.`;
    interfaceMetaText.textContent = `Interface: ${selected} | Type: ${inferredKind}`;
    return;
  }

  interfaceGuideText.textContent = details.osiHint;
  const descriptionText = details.description ? ` | Detail: ${details.description}` : "";
  const macText = details.macAddress ? ` | MAC: ${details.macAddress}` : "";
  interfaceMetaText.textContent = `Interface: ${details.name} | Type: ${details.kind}${descriptionText}${macText}`;
}

function setModelOptions(models, selectedFromStatus, requiresSelection) {
  modelSelect.innerHTML = "";
  state.selectedModel = null;

  if (!Array.isArray(models) || models.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Aucun modèle";
    modelSelect.appendChild(option);
    modelSelect.disabled = true;
    return;
  }

  if (requiresSelection) {
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Choisir un modèle";
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
      setAiStatus("statut IA invalide", true);
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
      setAiStatus(message || "connectée");
      return;
    }
    if (stateValue === "needs_selection") {
      setAiStatus(message || "sélection de modèle requise", true);
      return;
    }

    setAiStatus(message || "IA indisponible", true);
  } catch (error) {
    setAiStatus(`erreur check IA: ${String(error)}`, true);
    setModelOptions([], null, false);
  }
}

function resetSessionViews() {
  state.packets = [];
  state.droppedPackets = 0;
  state.currentPage = 1;
  state.selectedPacketId = null;
  state.selectedConversationKey = null;
  state.storyEvents = [];
  state.storySeen = new Set();
  state.conversations = new Map();
  state.aiCache = new Map();
  state.aiErrorCache = new Map();
  state.aiStreamRequestId = null;
  state.aiStreamBuffer = "";

  renderTablePage();
  renderExplanationEmpty();
  renderStoryList();
  renderFlowMap();
  renderHandshakeDecoder();
  resetFloatingAiChat();
}

function appendPackets(batch) {
  let batchBytes = 0;
  const previousPacketCount = state.packets.length;

  for (const packet of batch) {
    state.packets.push(packet);
    batchBytes += packet.length ?? 0;

    const convo = ensureConversation(packet);
    processStoryEvent(packet, convo);
    analyzePacketForAlerts(packet);
  }

  if (state.packets.length > MAX_STORED_PACKETS) {
    const overflow = state.packets.length - MAX_STORED_PACKETS;
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

  renderFlowMap();
  renderStoryList();
  renderHandshakeDecoder();
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
      option.textContent = "Aucune interface";
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
  renderFlowMap();
  renderStoryList();
  renderHandshakeDecoder();
  renderExplanation(packet);
  openFloatingAiChat();

  if (!state.selectedModel) {
    setAiStatus("sélection de modèle requise", true);
    showAiChatError(packet, "Sélectionne un modèle IA dans le header pour lancer l'analyse.", state.selectedModel);
    renderExplanation(packet, "", {
      aiError: "Sélectionne un modèle IA dans la barre du haut. La lecture locale reste disponible.",
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
  setAiStatus(`stream IA en cours (${state.selectedModel})`);

  try {
    await invoke("explain_packet_stream", {
      packet,
      model: state.selectedModel,
      requestId,
    });
  } catch (error) {
    state.aiErrorCache.set(cacheKey, String(error));
    if (state.selectedPacketId === packet.id) {
      showAiChatError(packet, String(error), state.selectedModel);
    }
    setAiStatus("erreur backend IA", true);
    await refreshAiStatus();
  }
}

export async function startCapture() {
  const iface = interfaceSelect.value;
  if (!iface) {
    setStatus("error", "interface requise");
    return;
  }

  resetSessionViews();
  resetTrafficState();
  resetAlertState();
  setAiStatus("vérification...");

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
    if (normalized.includes("déjà en cours") || normalized.includes("deja en cours")) {
      try {
        await invoke("stop_capture");
        await invoke("start_capture", { interface: iface });
        state.isCaptureRunning = true;
        setCaptureButtons(true);
        startGraphTicker();
        setStatus("running", "Capture resynchronisée");
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
  setStatus(payload.state, payload.message);

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
  setAiStatus(`connectée (${state.selectedModel})`);
}

export async function handleAiStreamError(payload) {
  if (!isExpectedStreamPayload(payload)) {
    return;
  }

  if (payload.request_id !== state.aiStreamRequestId) {
    return;
  }

  const message = String(payload.message || "stream IA interrompu");
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
