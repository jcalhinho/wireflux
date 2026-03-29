import { invoke } from "@tauri-apps/api/core";
import {
  docsBtn,
  exportPcapBtn,
  exportCsvBtn,
  exportJsonBtn,
  hoverTooltip,
  layerButtons,
  panelToggleButtons,
  ruleBeaconing,
  ruleBruteforce,
  ruleExfil,
  ruleSynScan,
  state,
} from "./domState.js";
import { getFilteredPackets } from "./helpers.js";

let onLivePanelExpanded = () => {};
let onLayerChange = () => {};

export function setUiHooks(hooks) {
  onLivePanelExpanded = hooks?.onLivePanelExpanded || onLivePanelExpanded;
  onLayerChange = hooks?.onLayerChange || onLayerChange;
}

function showTooltip(text, x, y) {
  if (!text) {
    hoverTooltip.classList.add("hidden");
    return;
  }

  hoverTooltip.textContent = text;
  hoverTooltip.classList.remove("hidden");

  const offset = 14;
  const maxLeft = window.innerWidth - hoverTooltip.offsetWidth - 12;
  const maxTop = window.innerHeight - hoverTooltip.offsetHeight - 12;
  const left = Math.min(maxLeft, x + offset);
  const top = Math.min(maxTop, y + offset);

  hoverTooltip.style.left = `${Math.max(8, left)}px`;
  hoverTooltip.style.top = `${Math.max(8, top)}px`;
}

function hideTooltip() {
  state.activeTooltipTarget = null;
  hoverTooltip.classList.add("hidden");
}

function flashMessage(message) {
  state.activeTooltipTarget = null;
  showTooltip(message, Math.max(16, window.innerWidth * 0.5), Math.max(16, window.innerHeight * 0.12));
  window.setTimeout(() => {
    hideTooltip();
  }, 1900);
}

export function initTooltipSystem() {
  document.addEventListener("mouseover", (event) => {
    const target = event.target.closest("[data-tip]");
    if (!target) {
      hideTooltip();
      return;
    }
    state.activeTooltipTarget = target;
    showTooltip(target.dataset.tip, event.clientX, event.clientY);
  });

  document.addEventListener("mousemove", (event) => {
    if (!state.activeTooltipTarget) {
      return;
    }
    showTooltip(state.activeTooltipTarget.dataset.tip, event.clientX, event.clientY);
  });

  document.addEventListener("mouseout", (event) => {
    if (!state.activeTooltipTarget) {
      return;
    }

    const leftTarget = event.target.closest("[data-tip]");
    if (leftTarget !== state.activeTooltipTarget) {
      return;
    }

    const entering = event.relatedTarget ? event.relatedTarget.closest("[data-tip]") : null;
    if (entering === state.activeTooltipTarget) {
      return;
    }

    hideTooltip();
  });
}

export function syncRulesFromUi() {
  state.rules.synScan = Boolean(ruleSynScan?.checked);
  state.rules.bruteforce = Boolean(ruleBruteforce?.checked);
  state.rules.beaconing = Boolean(ruleBeaconing?.checked);
  state.rules.exfil = Boolean(ruleExfil?.checked);
}

export function bindRulesEvents() {
  [ruleSynScan, ruleBruteforce, ruleBeaconing, ruleExfil].forEach((input) => {
    if (!input) {
      return;
    }
    input.addEventListener("change", () => {
      syncRulesFromUi();
    });
  });
}

function updatePanelToggleLabel(button, expanded) {
  const collapseLabel = button.dataset.labelCollapse || "Réduire";
  const expandLabel = button.dataset.labelExpand || "Déplier";
  button.textContent = expanded ? collapseLabel : expandLabel;
  button.setAttribute("aria-expanded", String(expanded));
}

export function bindPanelToggles() {
  for (const button of panelToggleButtons) {
    const panel = button.closest(".panel");
    if (!panel) {
      continue;
    }

    updatePanelToggleLabel(button, !panel.classList.contains("is-collapsed"));

    button.addEventListener("click", () => {
      const collapsed = panel.classList.toggle("is-collapsed");
      updatePanelToggleLabel(button, !collapsed);

      if (!collapsed && panel.classList.contains("live")) {
        onLivePanelExpanded();
      }
    });
  }
}

function updateLayerButtons(activeLayer) {
  for (const button of layerButtons) {
    const layer = String(button.dataset.layer || "").toLowerCase();
    button.classList.toggle("is-active", layer === activeLayer);
  }
}

export function bindLayerNavigation() {
  const initial =
    String(layerButtons.find((button) => button.classList.contains("is-active"))?.dataset.layer || "application")
      .toLowerCase();
  state.activeLayer = initial;
  updateLayerButtons(initial);

  for (const button of layerButtons) {
    button.addEventListener("click", () => {
      const layer = String(button.dataset.layer || "").toLowerCase();
      if (!layer || layer === state.activeLayer) {
        return;
      }
      state.activeLayer = layer;
      updateLayerButtons(layer);
      onLayerChange(layer);
    });
  }

  onLayerChange(initial);

  if (docsBtn) {
    docsBtn.addEventListener("click", () => {
      window.open("https://www.wireshark.org/docs/", "_blank", "noopener,noreferrer");
    });
  }

  if (exportPcapBtn) {
    exportPcapBtn.addEventListener("click", () => {
      void (async () => {
        try {
          const path = await invoke("export_pcap");
          flashMessage(`PCAP exporté: ${path}`);
        } catch (error) {
          flashMessage(`Export PCAP impossible: ${String(error)}`);
        }
      })();
    });
  }

  if (exportCsvBtn) {
    exportCsvBtn.addEventListener("click", () => {
      void (async () => {
        try {
          const packets = getFilteredPackets();
          const path = await invoke("export_packets", { packets, format: "csv" });
          flashMessage(`CSV exporté: ${path}`);
        } catch (error) {
          flashMessage(`Export CSV impossible: ${String(error)}`);
        }
      })();
    });
  }

  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", () => {
      void (async () => {
        try {
          const packets = getFilteredPackets();
          const path = await invoke("export_packets", { packets, format: "json" });
          flashMessage(`JSON exporté: ${path}`);
        } catch (error) {
          flashMessage(`Export JSON impossible: ${String(error)}`);
        }
      })();
    });
  }
}
