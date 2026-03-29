import { invoke } from "@tauri-apps/api/core";
import {
  MAX_STORED_PACKETS,
  conversationKeyForPacket,
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
import { prepareCoach, renderCoach, renderExplanation, renderExplanationEmpty } from "./explainCoach.js";
import { renderHandshakeDecoder } from "./handshakeView.js";
import { ensureConversation, processStoryEvent, renderFlowMap, renderStoryList } from "./storyFlow.js";
import { findPacketById, renderPageControls, renderTablePage } from "./tableView.js";

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
  prepareCoach({ id: 0, protocol: "", tcp_flags: null, destination_port: null, source_port: null });
  state.coach.quiz = null;
  renderCoach();
  renderStoryList();
  renderFlowMap();
  renderHandshakeDecoder();
}

function appendPackets(batch) {
  let batchBytes = 0;

  for (const packet of batch) {
    state.packets.push(packet);
    batchBytes += packet.length ?? 0;

    const convo = ensureConversation(packet);
    processStoryEvent(packet, convo);
    analyzePacketForAlerts(packet);
  }

  if (state.packets.length > MAX_STORED_PACKETS) {
    state.packets = state.packets.slice(-MAX_STORED_PACKETS);
  }

  state.currentSecondPackets += batch.length;
  state.currentSecondBytes += batchBytes;
  state.totalPackets += batch.length;

  if (state.currentPage === 1) {
    renderTablePage();
  } else {
    renderPageControls();
  }

  renderFlowMap();
  renderStoryList();
  renderHandshakeDecoder();
}

export async function loadInterfaces() {
  interfaceSelect.innerHTML = "";
  try {
    const interfaces = await invoke("list_interfaces");
    for (const name of interfaces) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      interfaceSelect.appendChild(option);
    }

    if (interfaces.length === 0) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "Aucune interface";
      interfaceSelect.appendChild(option);
    }
  } catch (error) {
    setStatus("error", `interfaces: ${String(error)}`);
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
  prepareCoach(packet);

  if (!state.selectedModel) {
    setAiStatus("sélection de modèle requise", true);
    renderExplanation(packet, "", {
      aiError: "Sélectionne un modèle IA dans la barre du haut. La lecture locale reste disponible.",
    });
    return;
  }

  const cacheKey = aiCacheKey(packet.id, state.selectedModel);
  const cachedAi = state.aiCache.get(cacheKey);
  const cachedError = state.aiErrorCache.get(cacheKey);

  if (cachedAi || cachedError) {
    renderExplanation(packet, cachedAi || "", { aiError: cachedError || "" });
    return;
  }

  const requestId = `${packet.id}-${Date.now()}`;
  state.aiStreamRequestId = requestId;
  state.aiStreamBuffer = "";
  renderExplanation(packet, "", { loading: true, streamText: "" });
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
      renderExplanation(packet, "", { aiError: String(error) });
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
    setStatus("error", String(error));
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

  renderExplanation(packet, "", {
    loading: true,
    streamText: state.aiStreamBuffer,
  });
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

  renderExplanation(packet, aiText);
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
      renderExplanation(packet, "", { aiError: message });
    }
  }

  setAiStatus(message, true);
  await refreshAiStatus();
}
