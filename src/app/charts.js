import { graphModal, largeChartEl, metricBps, metricPps, metricTotal, miniChartEl, setStatus, state } from "./domState.js";
import { maybeDetectTrafficSpike } from "./alerts.js";

export function chartOption() {
  return {
    animation: false,
    grid: { top: 18, right: 12, bottom: 24, left: 38 },
    tooltip: { trigger: "axis" },
    xAxis: {
      type: "category",
      data: state.timelineHistory,
      boundaryGap: false,
      axisLabel: { color: "#3d5d82", fontSize: 10 },
      axisLine: { lineStyle: { color: "#5f82aa" } },
    },
    yAxis: [
      {
        type: "value",
        name: "pkt/s",
        nameTextStyle: { color: "#1d4f85", fontSize: 10 },
        axisLabel: { color: "#3a618c", fontSize: 10 },
        splitLine: { lineStyle: { color: "rgba(41, 121, 255, 0.14)" } },
      },
      {
        type: "value",
        name: "B/s",
        nameTextStyle: { color: "#2d6eb8", fontSize: 10 },
        axisLabel: { color: "#3a618c", fontSize: 10 },
        splitLine: { show: false },
      },
    ],
    series: [
      {
        name: "Paquets/s",
        type: "line",
        smooth: true,
        showSymbol: false,
        data: state.ppsHistory,
        lineStyle: { width: 2, color: "#2979ff" },
        areaStyle: { color: "rgba(41, 121, 255, 0.16)" },
      },
      {
        name: "Bytes/s",
        type: "line",
        yAxisIndex: 1,
        smooth: true,
        showSymbol: false,
        data: state.bpsHistory,
        lineStyle: { width: 2, color: "#d45a00" },
        areaStyle: { color: "rgba(212, 90, 0, 0.14)" },
      },
    ],
  };
}

export function updateCharts() {
  if (!state.chartsReady || !state.miniChart || !state.largeChart) {
    return;
  }
  const option = chartOption();
  state.miniChart.setOption(option, true);
  state.largeChart.setOption(option, true);
}

export async function ensureChartsLoaded() {
  if (state.chartsReady) {
    return true;
  }

  if (state.chartsLoadingPromise) {
    return state.chartsLoadingPromise;
  }

  state.chartsLoadingPromise = import("../echarts-lite.js")
    .then((module) => {
      state.echartsApi = module.echarts;
      state.miniChart = state.echartsApi.init(miniChartEl);
      state.largeChart = state.echartsApi.init(largeChartEl);
      state.chartsReady = true;
      updateCharts();
      return true;
    })
    .catch((error) => {
      state.chartsReady = false;
      setStatus("error", `graph init: ${String(error)}`);
      return false;
    })
    .finally(() => {
      state.chartsLoadingPromise = null;
    });

  return state.chartsLoadingPromise;
}

export function updateMetricsUi(latestPps = 0, latestBps = 0) {
  metricPps.textContent = `${latestPps} pkt/s`;
  metricBps.textContent = `${latestBps} B/s`;
  metricTotal.textContent = `${state.totalPackets} paquets`;
}

export function resetTrafficState() {
  state.currentSecondPackets = 0;
  state.currentSecondBytes = 0;
  state.totalPackets = 0;
  state.ppsHistory = [];
  state.bpsHistory = [];
  state.timelineHistory = [];
  updateMetricsUi(0, 0);
  updateCharts();
}

export function startGraphTicker() {
  if (state.tickTimer) {
    return;
  }

  state.tickTimer = window.setInterval(() => {
    if (!state.isCaptureRunning) {
      return;
    }

    const latestPps = state.currentSecondPackets;
    const latestBps = state.currentSecondBytes;
    maybeDetectTrafficSpike(latestPps, latestBps);

    state.timelineHistory.push(
      new Date().toLocaleTimeString("fr-FR", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }),
    );
    state.ppsHistory.push(latestPps);
    state.bpsHistory.push(latestBps);

    if (state.ppsHistory.length > 90) {
      state.ppsHistory.shift();
      state.bpsHistory.shift();
      state.timelineHistory.shift();
    }

    updateMetricsUi(latestPps, latestBps);
    updateCharts();

    state.currentSecondPackets = 0;
    state.currentSecondBytes = 0;
  }, 1000);
}

export function stopGraphTicker() {
  if (!state.tickTimer) {
    return;
  }
  clearInterval(state.tickTimer);
  state.tickTimer = null;
}

export async function openGraphModal() {
  const ready = await ensureChartsLoaded();
  if (!ready) {
    return;
  }
  graphModal.classList.remove("hidden");
  graphModal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");
  state.largeChart?.resize();
  updateCharts();
}

export function closeGraphModal() {
  graphModal.classList.add("hidden");
  graphModal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
}
