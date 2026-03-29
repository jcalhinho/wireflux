import { listen } from "@tauri-apps/api/event";
import {
  closeGraphBtn,
  graphModal,
  modelSelect,
  nextPageBtn,
  openGraphBtn,
  packetFilterInput,
  prevPageBtn,
  profileSelect,
  refreshInterfacesBtn,
  setAiStatus,
  setStatus,
  state,
  startBtn,
  stopBtn,
  updateProfileStatus,
} from "./app/domState.js";
import { resetAlertState } from "./app/alerts.js";
import { closeGraphModal, openGraphModal, updateCharts, updateMetricsUi } from "./app/charts.js";
import {
  handleCaptureStatus,
  handleAiStreamChunk,
  handleAiStreamDone,
  handleAiStreamError,
  handlePacketBatch,
  loadInterfaces,
  refreshAiStatus,
  reselectCurrentPacket,
  selectPacket,
  startCapture,
  stopCapture,
} from "./app/capture.js";
import { renderCoach, renderExplanation, renderExplanationEmpty, setExplainHooks } from "./app/explainCoach.js";
import { renderHandshakeDecoder, setHandshakeHooks } from "./app/handshakeView.js";
import { renderFlowMap, renderStoryList, setStoryFlowHooks } from "./app/storyFlow.js";
import { findPacketById, renderTablePage, setTableHooks, totalPages } from "./app/tableView.js";
import {
  bindLayerNavigation,
  bindPanelToggles,
  bindRulesEvents,
  initTooltipSystem,
  setUiHooks,
  syncRulesFromUi,
} from "./app/uiControls.js";
import { aiCacheKey } from "./app/domState.js";

async function init() {
  setTableHooks({ onPacketSelect: selectPacket });
  setStoryFlowHooks({ onPacketSelect: selectPacket, findPacketById });
  setHandshakeHooks({ onPacketSelect: selectPacket, findPacketById });
  setExplainHooks({ findPacketById });
  setUiHooks({
    onLivePanelExpanded: () => state.miniChart?.resize(),
    onLayerChange: () => {
      renderTablePage();
      renderFlowMap();
      renderStoryList();
      renderHandshakeDecoder();
    },
  });

  initTooltipSystem();
  bindRulesEvents();
  bindPanelToggles();
  bindLayerNavigation();
  syncRulesFromUi();

  renderTablePage();
  renderExplanationEmpty();
  renderCoach();
  renderStoryList();
  renderFlowMap();
  renderHandshakeDecoder();
  resetAlertState();
  updateProfileStatus();

  refreshInterfacesBtn.addEventListener("click", async () => {
    await loadInterfaces();
    await refreshAiStatus();
  });

  startBtn.addEventListener("click", () => {
    void startCapture();
  });

  stopBtn.addEventListener("click", () => {
    void stopCapture();
  });

  packetFilterInput?.addEventListener("input", () => {
    state.packetFilter = String(packetFilterInput.value || "").trim();
    state.currentPage = 1;
    renderTablePage();
  });

  modelSelect.addEventListener("change", () => {
    state.selectedModel = modelSelect.value || null;
    if (state.selectedModel) {
      setAiStatus(`connectée (${state.selectedModel})`);
    } else {
      setAiStatus("sélection de modèle requise", true);
    }
    reselectCurrentPacket();
  });

  profileSelect.addEventListener("change", () => {
    state.profileMode = profileSelect.value || "auto";
    updateProfileStatus();

    if (state.selectedPacketId) {
      const packet = findPacketById(state.selectedPacketId);
      if (packet) {
        const key = aiCacheKey(packet.id, state.selectedModel);
        renderExplanation(packet, state.aiCache.get(key) || "", {
          aiError: state.aiErrorCache.get(key) || "",
        });
      }
    }
  });

  prevPageBtn.addEventListener("click", () => {
    if (state.currentPage > 1) {
      state.currentPage -= 1;
      renderTablePage();
    }
  });

  nextPageBtn.addEventListener("click", () => {
    if (state.currentPage < totalPages()) {
      state.currentPage += 1;
      renderTablePage();
    }
  });

  openGraphBtn.addEventListener("click", () => {
    void openGraphModal();
  });

  closeGraphBtn.addEventListener("click", closeGraphModal);
  graphModal.addEventListener("click", (event) => {
    if (event.target === graphModal) {
      closeGraphModal();
    }
  });

  window.addEventListener("resize", () => {
    state.miniChart?.resize();
    if (!graphModal.classList.contains("hidden")) {
      state.largeChart?.resize();
    }
  });

  await listen("capture-status", (event) => {
    void handleCaptureStatus(event.payload);
  });

  await listen("packet-batch", (event) => {
    handlePacketBatch(event.payload);
  });

  await listen("ai-stream-chunk", (event) => {
    handleAiStreamChunk(event.payload);
  });

  await listen("ai-stream-done", (event) => {
    handleAiStreamDone(event.payload);
  });

  await listen("ai-stream-error", (event) => {
    void handleAiStreamError(event.payload);
  });

  await loadInterfaces();
  setStatus("idle");
  setAiStatus("vérification...");
  await refreshAiStatus();
  updateMetricsUi(0, 0);
  updateCharts();
}

init().catch((error) => {
  setStatus("error", String(error));
  setAiStatus("erreur init", true);
});
