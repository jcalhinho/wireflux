import { invoke } from "@tauri-apps/api/core";
import {
  docsBtn,
  exportPcapBtn,
  exportCsvBtn,
  exportJsonBtn,
  hoverTooltip,
  LAYER_KEYS,
  layerAllButtons,
  layerButtons,
  panelToggleButtons,
  ruleBeaconing,
  ruleBruteforce,
  ruleExfil,
  ruleSynScan,
  shellRoot,
  state,
  toggleSidenavBtn,
} from "./domState.js";
import { getFilteredPackets } from "./helpers.js";
import { t } from "./i18n.js";

let onLivePanelExpanded = () => {};
let onLayerChange = () => {};
let onOpenDocs = null;
const SIDENAV_STATE_KEY = "wireflux:sidenav-collapsed";

export function setUiHooks(hooks) {
  onLivePanelExpanded = hooks?.onLivePanelExpanded || onLivePanelExpanded;
  onLayerChange = hooks?.onLayerChange || onLayerChange;
  onOpenDocs = hooks?.onOpenDocs || onOpenDocs;
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
  const collapseLabel = t("btn.collapse");
  const expandLabel = t("btn.expand");
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

function applySidenavCollapsed(collapsed) {
  if (!shellRoot) {
    return;
  }

  state.isSidenavCollapsed = Boolean(collapsed);
  shellRoot.classList.toggle("is-sidenav-collapsed", state.isSidenavCollapsed);

  if (!toggleSidenavBtn) {
    return;
  }

  toggleSidenavBtn.setAttribute("aria-expanded", String(!state.isSidenavCollapsed));

  const icon = toggleSidenavBtn.querySelector(".material-symbols-outlined");
  if (icon) {
    icon.textContent = state.isSidenavCollapsed ? "left_panel_open" : "left_panel_close";
  }

  const label = toggleSidenavBtn.querySelector(".wf-sidenav-toggle-label");
  if (label) {
    label.textContent = state.isSidenavCollapsed ? t("sidenav.open") : t("sidenav.collapse");
  }
}

export function bindSidenavToggle() {
  if (!shellRoot || !toggleSidenavBtn) {
    return;
  }

  let initialCollapsed = false;
  try {
    initialCollapsed = window.localStorage.getItem(SIDENAV_STATE_KEY) === "1";
  } catch (_error) {
    initialCollapsed = false;
  }
  applySidenavCollapsed(initialCollapsed);

  toggleSidenavBtn.addEventListener("click", () => {
    const nextCollapsed = !state.isSidenavCollapsed;
    applySidenavCollapsed(nextCollapsed);
    try {
      window.localStorage.setItem(SIDENAV_STATE_KEY, nextCollapsed ? "1" : "0");
    } catch (_error) {
      // no-op: persistence is optional
    }

    window.requestAnimationFrame(() => {
      window.dispatchEvent(new Event("resize"));
    });
  });
}

function updateLayerButtons() {
  const activeSet = state.allLayersActive ? new Set() : new Set(state.activeLayers);
  for (const button of layerButtons) {
    const layer = String(button.dataset.layer || "").toLowerCase();
    const isActive = !state.allLayersActive && activeSet.has(layer);
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-pressed", String(isActive));
  }

  for (const button of layerAllButtons) {
    button.classList.toggle("is-active", state.allLayersActive);
    button.setAttribute("aria-pressed", String(state.allLayersActive));
  }
}

export function bindAnalysisTabs() {
  const tabButtons = Array.from(document.querySelectorAll(".wf-tab-btn[data-tab]"));
  const tabPanels = Array.from(document.querySelectorAll(".wf-tab-panel[data-tab-panel]"));

  function activateTab(tabName) {
    for (const btn of tabButtons) {
      const active = btn.dataset.tab === tabName;
      btn.classList.toggle("is-active", active);
      btn.setAttribute("aria-selected", String(active));
    }
    for (const panel of tabPanels) {
      panel.classList.toggle("is-active", panel.dataset.tabPanel === tabName);
    }
  }

  for (const btn of tabButtons) {
    btn.addEventListener("click", () => {
      activateTab(btn.dataset.tab);
    });
  }
}

export function bindLayerNavigation() {
  state.allLayersActive = true;
  state.activeLayers = new Set();
  updateLayerButtons();

  for (const button of layerButtons) {
    button.addEventListener("click", () => {
      const layer = String(button.dataset.layer || "").toLowerCase();
      if (!layer || !LAYER_KEYS.includes(layer)) {
        return;
      }

      if (state.allLayersActive) {
        state.allLayersActive = false;
        state.activeLayers = new Set([layer]);
      } else if (state.activeLayers.has(layer)) {
        state.activeLayers.delete(layer);
      } else {
        state.activeLayers.add(layer);
      }

      if (state.activeLayers.size === 0) {
        state.allLayersActive = true;
      }

      state.currentPage = 1;
      updateLayerButtons();
      onLayerChange(Array.from(state.activeLayers));
    });
  }

  for (const button of layerAllButtons) {
    button.addEventListener("click", () => {
      state.allLayersActive = true;
      state.activeLayers = new Set();
      state.currentPage = 1;
      updateLayerButtons();
      onLayerChange([]);
    });
  }

  onLayerChange([]);

  if (docsBtn) {
    docsBtn.addEventListener("click", () => {
      if (typeof onOpenDocs === "function") {
        void onOpenDocs();
        return;
      }
      const docsUrl = new URL("docs/index.html", window.location.href).toString();
      const opened = window.open(docsUrl, "_blank", "noopener,noreferrer");
      if (!opened) {
        window.location.href = docsUrl;
      }
    });
  }

  if (exportPcapBtn) {
    exportPcapBtn.addEventListener("click", () => {
      void (async () => {
        try {
          const path = await invoke("export_pcap");
          flashMessage(t("export.pcap.ok", { path }));
        } catch (error) {
          flashMessage(t("export.pcap.error", { error: String(error) }));
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
          flashMessage(t("export.csv.ok", { path }));
        } catch (error) {
          flashMessage(t("export.csv.error", { error: String(error) }));
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
          flashMessage(t("export.json.ok", { path }));
        } catch (error) {
          flashMessage(t("export.json.error", { error: String(error) }));
        }
      })();
    });
  }
}
