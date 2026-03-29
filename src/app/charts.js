import { graphModal, largeChartEl, MAX_STORED_PACKETS, metricBps, metricPps, metricTotal, miniChartEl, setStatus, state } from "./domState.js";
import { maybeDetectTrafficSpike } from "./alerts.js";
import { getLayerFilteredPackets, resolveOsiLayer } from "./helpers.js";

const MAX_GRAPH_BARS = 72;
const MINI_MAX_LABELS = 8;
const LARGE_MAX_LABELS = 18;
const LAYER_LEVELS = {
  l2: 1,
  l3: 2,
  l4: 3,
  l5: 4,
  l6: 5,
  l7: 6,
};
const LAYER_LABELS = {
  1: "L2 Data Link",
  2: "L3 Network",
  3: "L4 Transport",
  4: "L5 Session",
  5: "L6 Presentation",
  6: "L7 Application",
};
const LAYER_COLORS = {
  1: "#7c3aed",
  2: "#d97706",
  3: "#0f6df3",
  4: "#0ea5b8",
  5: "#19a97d",
  6: "#0d9466",
};

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes >= 1_000_000_000) {
    return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
  }
  if (bytes >= 1_000_000) {
    return `${(bytes / 1_000_000).toFixed(2)} MB`;
  }
  if (bytes >= 1_000) {
    return `${(bytes / 1_000).toFixed(1)} KB`;
  }
  return `${bytes} B`;
}

function buildPacketBuckets() {
  const packets = getLayerFilteredPackets();
  if (!Array.isArray(packets) || packets.length === 0) {
    return {
      labels: [],
      byteTotals: [],
      packetCounts: [],
      averageSizes: [],
      layerMaxLevels: [],
      ranges: [],
      bucketSize: 1,
    };
  }

  const totalPackets = packets.length;
  const bucketSize = Math.max(1, Math.ceil(totalPackets / MAX_GRAPH_BARS));
  const labels = [];
  const byteTotals = [];
  const packetCounts = [];
  const averageSizes = [];
  const layerMaxLevels = [];
  const ranges = [];

  for (let startIndex = 0; startIndex < totalPackets; startIndex += bucketSize) {
    const endIndex = Math.min(totalPackets - 1, startIndex + bucketSize - 1);
    const slice = packets.slice(startIndex, endIndex + 1);
    const bytes = slice.reduce((sum, packet) => sum + Number(packet.length || 0), 0);
    const count = slice.length;
    const avg = count > 0 ? bytes / count : 0;
    const first = slice[0];
    const last = slice[count - 1];
    const layerVotes = new Map([
      [1, 0],
      [2, 0],
      [3, 0],
      [4, 0],
      [5, 0],
      [6, 0],
    ]);

    for (const packet of slice) {
      const layerKey = resolveOsiLayer(packet);
      const level = LAYER_LEVELS[layerKey] || 1;
      layerVotes.set(level, (layerVotes.get(level) || 0) + 1);
    }

    let dominantLayer = 1;
    let dominantCount = -1;
    for (const [level, countValue] of layerVotes.entries()) {
      if (countValue > dominantCount || (countValue === dominantCount && level > dominantLayer)) {
        dominantLayer = level;
        dominantCount = countValue;
      }
    }

    labels.push(bucketSize === 1 ? `#${last.id}` : `#${first.id}-#${last.id}`);
    byteTotals.push(bytes);
    packetCounts.push(count);
    averageSizes.push(Number(avg.toFixed(1)));
    layerMaxLevels.push(dominantLayer);
    ranges.push({
      fromId: first.id,
      toId: last.id,
      fromTs: first.timestamp,
      toTs: last.timestamp,
    });
  }

  return {
    labels,
    byteTotals,
    packetCounts,
    averageSizes,
    layerMaxLevels,
    ranges,
    bucketSize,
  };
}

function tooltipFormatter(params, buckets) {
  if (!Array.isArray(params) || params.length === 0) {
    return "Aucune donnée";
  }

  const dataIndex = Number(params[0]?.dataIndex ?? -1);
  const range = buckets.ranges[dataIndex];
  if (!range) {
    return "Aucune donnée";
  }

  const lines = [];
  lines.push(`Paquets: #${range.fromId} -> #${range.toId}`);
  lines.push(`Fenêtre: ${range.fromTs} -> ${range.toTs}`);
  const reachedLayer = buckets.layerMaxLevels[dataIndex] || 1;
  lines.push(`Couche dominante: ${LAYER_LABELS[reachedLayer] || "L2 Data Link"}`);

  for (const point of params) {
    const marker = point.marker || "";
    const value = Number(point.value || 0);
    if (point.seriesName.includes("Octets")) {
      lines.push(`${marker}${point.seriesName}: ${formatBytes(value)}`);
    } else if (point.seriesName.includes("Moyenne")) {
      lines.push(`${marker}${point.seriesName}: ${value.toFixed(1)} B`);
    } else {
      lines.push(`${marker}${point.seriesName}: ${value}`);
    }
  }

  return lines.join("<br/>");
}

function axisLabelInterval(total, compact) {
  const target = compact ? MINI_MAX_LABELS : LARGE_MAX_LABELS;
  return total > target ? Math.ceil(total / target) - 1 : 0;
}

export function chartOption(compact = false) {
  const buckets = buildPacketBuckets();
  const labelInterval = axisLabelInterval(buckets.labels.length, compact);
  const bytesSeriesLabel =
    buckets.bucketSize === 1 ? "Octets par paquet" : `Octets par tranche (${buckets.bucketSize} paquets)`;

  return {
    animation: false,
    legend: compact
      ? { show: false }
      : {
          top: 4,
          textStyle: { color: "#355277", fontSize: 11 },
        },
    grid: compact
      ? { top: 12, right: 10, bottom: 28, left: 44 }
      : { top: 30, right: 16, bottom: 56, left: 58 },
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params) => tooltipFormatter(params, buckets),
    },
    dataZoom: compact
      ? [{ type: "inside", xAxisIndex: 0 }]
      : [
          { type: "inside", xAxisIndex: 0 },
          {
            type: "slider",
            bottom: 10,
            height: 20,
            xAxisIndex: 0,
            borderColor: "#b6c8e2",
            fillerColor: "rgba(41, 121, 255, 0.18)",
            moveHandleSize: 10,
          },
        ],
    xAxis: {
      type: "category",
      data: buckets.labels,
      boundaryGap: true,
      axisLabel: {
        color: "#3d5d82",
        fontSize: compact ? 9 : 10,
        interval: labelInterval,
      },
      axisLine: { lineStyle: { color: "#5f82aa" } },
    },
    yAxis: [
      {
        type: "value",
        name: "Octets",
        nameTextStyle: { color: "#1d4f85", fontSize: 10 },
        axisLabel: { color: "#3a618c", fontSize: 10 },
        splitLine: { lineStyle: { color: "rgba(41, 121, 255, 0.14)" } },
      },
      {
        type: "value",
        name: "Paquets",
        nameTextStyle: { color: "#2d6eb8", fontSize: 10 },
        axisLabel: { color: "#3a618c", fontSize: 10 },
        splitLine: { show: false },
      },
      {
        type: "value",
        name: compact ? "" : "Couche dominante",
        min: 1,
        max: 6,
        interval: 1,
        axisLabel: {
          color: "#3a618c",
          fontSize: 9,
          formatter: (value) => (compact ? "" : LAYER_LABELS[value] || ""),
        },
        axisLine: { show: !compact, lineStyle: { color: "#5f82aa" } },
        axisTick: { show: !compact },
        splitLine: { show: false },
      },
    ],
    visualMap: [
      {
        show: false,
        seriesIndex: 3,
        dimension: 1,
        pieces: [
          { value: 1, color: LAYER_COLORS[1] },
          { value: 2, color: LAYER_COLORS[2] },
          { value: 3, color: LAYER_COLORS[3] },
          { value: 4, color: LAYER_COLORS[4] },
          { value: 5, color: LAYER_COLORS[5] },
          { value: 6, color: LAYER_COLORS[6] },
        ],
      },
    ],
    series: [
      {
        name: bytesSeriesLabel,
        type: "bar",
        data: buckets.byteTotals,
        barMaxWidth: compact ? 12 : 18,
        itemStyle: {
          color: "rgba(41, 121, 255, 0.65)",
          borderRadius: [4, 4, 0, 0],
        },
        emphasis: {
          itemStyle: {
            color: "rgba(41, 121, 255, 0.9)",
          },
        },
      },
      {
        name: "Paquets par tranche",
        type: "line",
        yAxisIndex: 1,
        smooth: true,
        showSymbol: false,
        data: buckets.packetCounts,
        lineStyle: { width: 2, color: "#d45a00" },
        areaStyle: { color: "rgba(212, 90, 0, 0.11)" },
      },
      {
        name: "Moyenne octets/paquet",
        type: "line",
        smooth: true,
        showSymbol: false,
        data: buckets.averageSizes,
        lineStyle: { width: 1.4, color: "#0f8b72", type: "dashed" },
      },
      {
        name: "Couche dominante (step)",
        type: "line",
        yAxisIndex: 2,
        step: "end",
        smooth: false,
        showSymbol: false,
        data: buckets.layerMaxLevels,
        lineStyle: { width: 2.2 },
        areaStyle: compact ? { opacity: 0 } : { color: "rgba(23, 74, 142, 0.08)" },
        markArea: compact
          ? undefined
          : {
              silent: true,
              data: [
                [{ yAxis: 0.5, itemStyle: { color: "rgba(124, 58, 237, 0.08)" } }, { yAxis: 1.5 }],
                [{ yAxis: 1.5, itemStyle: { color: "rgba(217, 119, 6, 0.08)" } }, { yAxis: 2.5 }],
                [{ yAxis: 2.5, itemStyle: { color: "rgba(15, 109, 243, 0.08)" } }, { yAxis: 3.5 }],
                [{ yAxis: 3.5, itemStyle: { color: "rgba(14, 165, 184, 0.08)" } }, { yAxis: 4.5 }],
                [{ yAxis: 4.5, itemStyle: { color: "rgba(25, 169, 125, 0.08)" } }, { yAxis: 5.5 }],
                [{ yAxis: 5.5, itemStyle: { color: "rgba(13, 148, 102, 0.08)" } }, { yAxis: 6.5 }],
              ],
            },
      },
    ],
  };
}

export function updateCharts() {
  if (!state.chartsReady || !state.miniChart || !state.largeChart) {
    return;
  }
  state.miniChart.setOption(chartOption(true), true);
  state.largeChart.setOption(chartOption(false), true);
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
  if (state.droppedPackets > 0) {
    metricTotal.textContent = `${state.totalPackets} paquets • fenêtre ${state.packets.length}/${MAX_STORED_PACKETS} (+${state.droppedPackets} purgés)`;
    return;
  }
  metricTotal.textContent = `${state.totalPackets} paquets • fenêtre ${state.packets.length}/${MAX_STORED_PACKETS}`;
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
