export const interfaceSelect = document.getElementById("interfaceSelect");
export const modelSelect = document.getElementById("modelSelect");
export const profileSelect = document.getElementById("profileSelect");
export const refreshInterfacesBtn = document.getElementById("refreshInterfacesBtn");
export const startBtn = document.getElementById("startBtn");
export const stopBtn = document.getElementById("stopBtn");

export const statusText = document.getElementById("statusText");
export const aiStatusText = document.getElementById("aiStatusText");
export const profileStatusText = document.getElementById("profileStatusText");

export const packetBody = document.getElementById("packetBody");
export const explanationView = document.getElementById("explanationView");
export const coachView = document.getElementById("coachView");
export const handshakeView = document.getElementById("handshakeView");
export const storyList = document.getElementById("storyList");
export const flowMap = document.getElementById("flowMap");
export const alertList = document.getElementById("alertList");

export const metricPps = document.getElementById("metricPps");
export const metricBps = document.getElementById("metricBps");
export const metricTotal = document.getElementById("metricTotal");

export const pageText = document.getElementById("pageText");
export const prevPageBtn = document.getElementById("prevPageBtn");
export const nextPageBtn = document.getElementById("nextPageBtn");

export const packetFilterInput = document.getElementById("packetFilterInput");
export const openGraphBtn = document.getElementById("openGraphBtn");
export const closeGraphBtn = document.getElementById("closeGraphBtn");
export const graphModal = document.getElementById("graphModal");
export const miniChartEl = document.getElementById("trafficChartMini");
export const largeChartEl = document.getElementById("trafficChartLarge");

export const ruleSynScan = document.getElementById("ruleSynScan");
export const ruleBruteforce = document.getElementById("ruleBruteforce");
export const ruleBeaconing = document.getElementById("ruleBeaconing");
export const ruleExfil = document.getElementById("ruleExfil");
export const panelToggleButtons = Array.from(document.querySelectorAll("[data-panel-toggle]"));

export const hoverTooltip = document.getElementById("hoverTooltip");
export const alertCountBadge = document.getElementById("alertCountBadge");
export const layerButtons = Array.from(document.querySelectorAll("[data-layer]"));
export const exportPcapBtn = document.getElementById("exportPcapBtn");
export const exportCsvBtn = document.getElementById("exportCsvBtn");
export const exportJsonBtn = document.getElementById("exportJsonBtn");
export const docsBtn = document.getElementById("docsBtn");

export const MAX_STORED_PACKETS = 10_000;
export const PAGE_SIZE = 14;
export const MAX_POINTS = 90;
export const MAX_ALERTS = 80;
export const MAX_STORY_EVENTS = 180;
export const MAX_FLOW_ITEMS = 24;

export const SYN_SCAN_WINDOW_MS = 15_000;
export const SYN_SCAN_PORT_THRESHOLD = 12;
export const BRUTE_FORCE_WINDOW_MS = 20_000;
export const BRUTE_FORCE_ATTEMPTS_THRESHOLD = 8;
export const BEACON_WINDOW_MS = 120_000;
export const BEACON_MIN_SAMPLES = 6;
export const BEACON_MIN_INTERVAL_MS = 2_000;
export const BEACON_MAX_INTERVAL_MS = 90_000;
export const BEACON_MAX_CV = 0.25;
export const EXFIL_WINDOW_MS = 10_000;
export const EXFIL_BYTES_THRESHOLD = 600_000;
export const EXFIL_PACKET_THRESHOLD = 24;
export const TRAFFIC_SPIKE_WINDOW_POINTS = 12;
export const ALERT_COOLDOWN_MS = 20_000;

export const KNOWN_PORTS = new Map([
  [20, "FTP Data"],
  [21, "FTP Control"],
  [22, "SSH"],
  [23, "Telnet"],
  [25, "SMTP"],
  [53, "DNS"],
  [67, "DHCP Server"],
  [68, "DHCP Client"],
  [80, "HTTP"],
  [110, "POP3"],
  [123, "NTP"],
  [135, "RPC"],
  [137, "NetBIOS Name"],
  [138, "NetBIOS Datagram"],
  [139, "NetBIOS Session"],
  [143, "IMAP"],
  [161, "SNMP"],
  [389, "LDAP"],
  [443, "HTTPS"],
  [445, "SMB"],
  [587, "SMTP Submission"],
  [636, "LDAPS"],
  [993, "IMAPS"],
  [995, "POP3S"],
  [1433, "MSSQL"],
  [1521, "Oracle DB"],
  [3306, "MySQL"],
  [3389, "RDP"],
  [5432, "PostgreSQL"],
  [5900, "VNC"],
  [6379, "Redis"],
  [8080, "HTTP Alt"],
  [8443, "HTTPS Alt"],
]);

export const SENSITIVE_PORTS = new Set([
  21,
  22,
  23,
  25,
  80,
  110,
  135,
  139,
  143,
  389,
  443,
  445,
  3389,
  5432,
  5900,
  6379,
  8080,
]);

export const state = {
  packets: [],
  selectedPacketId: null,
  selectedConversationKey: null,
  selectedModel: null,
  currentPage: 1,
  isCaptureRunning: false,
  tickTimer: null,
  currentSecondPackets: 0,
  currentSecondBytes: 0,
  totalPackets: 0,
  ppsHistory: [],
  bpsHistory: [],
  timelineHistory: [],
  alerts: [],
  nextAlertId: 1,
  storyEvents: [],
  storySeen: new Set(),
  conversations: new Map(),
  synScanState: new Map(),
  bruteForceState: new Map(),
  beaconingState: new Map(),
  exfilState: new Map(),
  trafficSpikeLastAlertAt: 0,
  miniChart: null,
  largeChart: null,
  chartsReady: false,
  chartsLoadingPromise: null,
  echartsApi: null,
  activeTooltipTarget: null,
  profileMode: "auto",
  activeLayer: "application",
  quizCorrect: 0,
  quizAnswered: 0,
  coach: {
    packetId: null,
    quiz: null,
    answered: false,
    selectedIndex: null,
  },
  packetFilter: "",
  aiCache: new Map(),
  aiErrorCache: new Map(),
  aiStreamRequestId: null,
  aiStreamBuffer: "",
  rules: {
    synScan: true,
    bruteforce: true,
    beaconing: true,
    exfil: true,
  },
};

export function setStatus(status, message = "") {
  statusText.textContent = message || status;
  statusText.classList.remove("status-running", "status-error");
  if (status === "running") {
    statusText.classList.add("status-running");
  }
  if (status === "error") {
    statusText.classList.add("status-error");
  }
}

export function setAiStatus(text, isError = false) {
  aiStatusText.textContent = text;
  aiStatusText.classList.toggle("status-error", isError);
}

export function setCaptureButtons(isRunning) {
  startBtn.disabled = isRunning;
  stopBtn.disabled = !isRunning;
}

export function resolveProfileMode() {
  if (state.profileMode === "beginner" || state.profileMode === "expert") {
    return state.profileMode;
  }

  const answered = state.quizAnswered;
  const ratio = answered > 0 ? state.quizCorrect / answered : 0;
  if (answered < 4) {
    return "beginner";
  }
  return ratio >= 0.7 ? "expert" : "beginner";
}

export function updateProfileStatus() {
  const resolved = resolveProfileMode();
  profileStatusText.textContent = `${state.profileMode} (${resolved})`;
}

export function aiCacheKey(packetId, modelName) {
  return `${modelName || "none"}::${packetId}`;
}

export function conversationKeyForPacket(packet) {
  return [packet.source, packet.source_port, packet.destination, packet.destination_port, packet.protocol].join("|");
}

export function flowDirectionKey(packet) {
  return `${packet.source}->${packet.destination}:${packet.destination_port}:${packet.protocol}`;
}
