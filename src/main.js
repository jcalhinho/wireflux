import { listen } from "@tauri-apps/api/event";
import {
  closeGraphBtn,
  graphModal,
  interfaceSelect,
  modelSelect,
  nextPageBtn,
  openGraphBtn,
  pageSizeSelect,
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
import { renderAlerts, resetAlertState } from "./app/alerts.js";
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
  updateInterfaceEducation,
} from "./app/capture.js";
import { renderCoach, renderExplanation, renderExplanationEmpty, setExplainHooks } from "./app/explainCoach.js";
import { initFloatingAiChat, resetFloatingAiChat } from "./app/floatingAiChat.js";
import { applyLang, t } from "./app/i18n.js";
import { renderHandshakeDecoder, setHandshakeHooks } from "./app/handshakeView.js";
import { findPacketById, renderTablePage, setTableHooks, totalPages } from "./app/tableView.js";
import {
  bindAnalysisTabs,
  bindLayerNavigation,
  bindPanelToggles,
  bindRulesEvents,
  bindSidenavToggle,
  initTooltipSystem,
  setUiHooks,
  syncRulesFromUi,
} from "./app/uiControls.js";
import { aiCacheKey } from "./app/domState.js";

async function init() {
  setTableHooks({ onPacketSelect: selectPacket });
  setHandshakeHooks({ onPacketSelect: selectPacket, findPacketById });
  setExplainHooks({ findPacketById });
  setUiHooks({
    onLivePanelExpanded: () => state.miniChart?.resize(),
    onLayerChange: () => {
      renderTablePage();
      renderHandshakeDecoder();
      updateCharts();
    },
    onOpenDocs: async () => {
      const docsUrl = new URL("docs/index.html", window.location.href).toString();
      const opened = window.open(docsUrl, "_blank", "noopener,noreferrer");
      if (opened) {
        return;
      }

      if (state.isCaptureRunning) {
        await stopCapture();
      }
      window.location.href = docsUrl;
    },
  });

  initTooltipSystem();
  bindAnalysisTabs();
  bindRulesEvents();
  bindPanelToggles();
  bindSidenavToggle();
  bindLayerNavigation();
  initFloatingAiChat();
  syncRulesFromUi();
  applyLang(state.lang);

  const langToggleBtn = document.getElementById("langToggleBtn");
  if (langToggleBtn) {
    langToggleBtn.addEventListener("click", () => {
      state.lang = state.lang === "fr" ? "en" : "fr";
      applyLang(state.lang);
      updateInterfaceEducation();
      renderTablePage();
      renderHandshakeDecoder();
      renderAlerts();
      updateProfileStatus();
      renderCoach();
      const packet = state.selectedPacketId ? findPacketById(state.selectedPacketId) : null;
      if (packet) {
        const key = aiCacheKey(packet.id, state.selectedModel);
        renderExplanation(packet, state.aiCache.get(key) || "", {
          aiError: state.aiErrorCache.get(key) || "",
        });
      } else {
        renderExplanationEmpty();
      }
      updateMetricsUi(state.ppsHistory.at(-1) || 0, state.bpsHistory.at(-1) || 0);
    });
  }

  renderTablePage();
  renderExplanationEmpty();
  renderHandshakeDecoder();
  resetFloatingAiChat();
  resetAlertState();
  updateProfileStatus();

  refreshInterfacesBtn.addEventListener("click", async () => {
    await loadInterfaces();
    await refreshAiStatus();
  });

  interfaceSelect?.addEventListener("change", () => {
    updateInterfaceEducation();
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
      setAiStatus(t("status.ai.connected.model", { model: state.selectedModel }));
    } else {
      setAiStatus(t("status.model.required"), true);
    }
    reselectCurrentPacket();
  });

  if (profileSelect) {
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
  }

  pageSizeSelect?.addEventListener("change", () => {
    const nextSize = Number.parseInt(String(pageSizeSelect.value || "20"), 10);
    state.pageSize = Number.isFinite(nextSize) && nextSize > 0 ? nextSize : 20;
    state.currentPage = 1;
    renderTablePage();
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
  setAiStatus(t("status.connecting"));
  await refreshAiStatus();
  updateMetricsUi(0, 0);
  updateCharts();
}

init().catch((error) => {
  setStatus("error", String(error));
  setAiStatus(t("status.init.error"), true);
});
