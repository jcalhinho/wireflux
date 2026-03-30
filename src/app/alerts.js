import {
  ALERT_COOLDOWN_MS,
  BEACON_MAX_CV,
  BEACON_MAX_INTERVAL_MS,
  BEACON_MIN_INTERVAL_MS,
  BEACON_MIN_SAMPLES,
  BEACON_WINDOW_MS,
  BRUTE_FORCE_ATTEMPTS_THRESHOLD,
  BRUTE_FORCE_WINDOW_MS,
  EXFIL_BYTES_THRESHOLD,
  EXFIL_PACKET_THRESHOLD,
  EXFIL_WINDOW_MS,
  MAX_ALERTS,
  SENSITIVE_PORTS,
  SYN_SCAN_PORT_THRESHOLD,
  SYN_SCAN_WINDOW_MS,
  TRAFFIC_SPIKE_WINDOW_POINTS,
  alertCountBadge,
  alertList,
  flowDirectionKey,
  state,
} from "./domState.js";
import { isPrivateIp, parseTcpFlags, safeToLocaleTime, serviceNameForPort } from "./helpers.js";
import { t } from "./i18n.js";

export function renderAlerts() {
  alertList.innerHTML = "";

  if (state.alerts.length === 0) {
    const emptyItem = document.createElement("li");
    emptyItem.className = "alert-empty";
    emptyItem.textContent = t("alerts.empty");
    alertList.appendChild(emptyItem);
    if (alertCountBadge) {
      alertCountBadge.textContent = "0";
      alertCountBadge.classList.add("hidden");
    }
    return;
  }

  if (alertCountBadge) {
    alertCountBadge.textContent = String(state.alerts.length);
    alertCountBadge.classList.remove("hidden");
  }

  for (const alert of state.alerts) {
    const item = document.createElement("li");
    item.className = "alert-item";

    const top = document.createElement("div");
    top.className = "alert-top";

    const severity = document.createElement("span");
    severity.className = `alert-severity alert-${alert.severity}`;
    severity.textContent = alert.severity.toUpperCase();

    const title = document.createElement("strong");
    title.textContent = alert.title;

    const time = document.createElement("time");
    time.textContent = safeToLocaleTime(alert.at);

    const detail = document.createElement("p");
    detail.textContent = alert.detail;

    top.appendChild(severity);
    top.appendChild(title);
    top.appendChild(time);
    item.appendChild(top);
    item.appendChild(detail);
    item.dataset.tip = `${alert.title}\n${alert.detail}`;

    alertList.appendChild(item);
  }
}

export function pushAlert(severity, title, detail) {
  state.alerts.unshift({
    id: state.nextAlertId,
    severity,
    title,
    detail,
    at: Date.now(),
  });
  state.nextAlertId += 1;

  if (state.alerts.length > MAX_ALERTS) {
    state.alerts = state.alerts.slice(0, MAX_ALERTS);
  }

  renderAlerts();
}

export function resetAlertState() {
  state.alerts = [];
  state.nextAlertId = 1;
  state.synScanState = new Map();
  state.bruteForceState = new Map();
  state.beaconingState = new Map();
  state.exfilState = new Map();
  state.trafficSpikeLastAlertAt = 0;
  renderAlerts();
}

function maybeDetectSynScan(packet, now) {
  if (!state.rules.synScan) {
    return;
  }
  if (packet.destination_port === null || packet.destination_port === undefined) {
    return;
  }

  const sourceKey = packet.source || "unknown";
  const current = state.synScanState.get(sourceKey) || { attempts: [], lastAlertAt: 0 };

  current.attempts.push({
    at: now,
    destination: packet.destination,
    destinationPort: packet.destination_port,
  });
  current.attempts = current.attempts.filter((entry) => now - entry.at <= SYN_SCAN_WINDOW_MS);

  const uniqueTargets = new Set(current.attempts.map((entry) => `${entry.destination}:${entry.destinationPort}`));
  if (uniqueTargets.size >= SYN_SCAN_PORT_THRESHOLD && now - current.lastAlertAt >= ALERT_COOLDOWN_MS) {
    pushAlert(
      "high",
      t("alert.synscan.title"),
      t("alert.synscan.detail", {
        source: sourceKey,
        count: uniqueTargets.size,
        seconds: Math.round(SYN_SCAN_WINDOW_MS / 1000),
      }),
    );
    current.lastAlertAt = now;
  }

  state.synScanState.set(sourceKey, current);
}

function maybeDetectBruteforce(packet, now) {
  if (!state.rules.bruteforce) {
    return;
  }

  const destinationPort = packet.destination_port;
  if (destinationPort === null || destinationPort === undefined || !SENSITIVE_PORTS.has(destinationPort)) {
    return;
  }

  const key = `${packet.source}->${packet.destination}:${destinationPort}`;
  const current = state.bruteForceState.get(key) || { attempts: [], lastAlertAt: 0 };
  current.attempts.push(now);
  current.attempts = current.attempts.filter((timestamp) => now - timestamp <= BRUTE_FORCE_WINDOW_MS);

  if (
    current.attempts.length >= BRUTE_FORCE_ATTEMPTS_THRESHOLD &&
    now - current.lastAlertAt >= ALERT_COOLDOWN_MS
  ) {
    pushAlert(
      "medium",
      t("alert.bruteforce.title"),
      t("alert.bruteforce.detail", {
        source: packet.source,
        destination: packet.destination,
        port: destinationPort,
        service: serviceNameForPort(destinationPort),
        attempts: current.attempts.length,
      }),
    );
    current.lastAlertAt = now;
  }

  state.bruteForceState.set(key, current);
}

function mean(values) {
  if (values.length === 0) {
    return 0;
  }
  return values.reduce((acc, value) => acc + value, 0) / values.length;
}

function stddev(values, average) {
  if (values.length === 0) {
    return 0;
  }
  const variance = values.reduce((acc, value) => acc + (value - average) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

function maybeDetectBeaconing(packet, now) {
  if (!state.rules.beaconing) {
    return;
  }

  const proto = String(packet.protocol || "").toUpperCase();
  if (proto !== "TCP" && proto !== "UDP") {
    return;
  }
  if ((packet.length || 0) < 50 || (packet.length || 0) > 260) {
    return;
  }

  const key = flowDirectionKey(packet);
  const current = state.beaconingState.get(key) || { timestamps: [], lastAlertAt: 0 };
  current.timestamps.push(now);
  current.timestamps = current.timestamps.filter((timestamp) => now - timestamp <= BEACON_WINDOW_MS);

  if (current.timestamps.length >= BEACON_MIN_SAMPLES) {
    const intervals = [];
    for (let index = 1; index < current.timestamps.length; index += 1) {
      intervals.push(current.timestamps[index] - current.timestamps[index - 1]);
    }

    const avg = mean(intervals);
    const sigma = stddev(intervals, avg);
    const cv = avg > 0 ? sigma / avg : 1;

    if (
      avg >= BEACON_MIN_INTERVAL_MS &&
      avg <= BEACON_MAX_INTERVAL_MS &&
      cv <= BEACON_MAX_CV &&
      now - current.lastAlertAt >= ALERT_COOLDOWN_MS
    ) {
      pushAlert(
        "medium",
        t("alert.beacon.title"),
        t("alert.beacon.detail", {
          source: packet.source,
          destination: packet.destination,
          port: packet.destination_port ?? "?",
          avg: Math.round(avg / 1000),
          cv: cv.toFixed(2),
        }),
      );
      current.lastAlertAt = now;
    }
  }

  state.beaconingState.set(key, current);
}

function maybeDetectExfilBurst(packet, now) {
  if (!state.rules.exfil) {
    return;
  }

  const sourcePrivate = isPrivateIp(packet.source);
  const destinationPrivate = isPrivateIp(packet.destination);
  if (!sourcePrivate || destinationPrivate) {
    return;
  }

  const key = `${packet.source}->${packet.destination}`;
  const current = state.exfilState.get(key) || { events: [], lastAlertAt: 0 };

  current.events.push({ at: now, bytes: packet.length || 0 });
  current.events = current.events.filter((event) => now - event.at <= EXFIL_WINDOW_MS);

  const bytes = current.events.reduce((sum, event) => sum + event.bytes, 0);
  const packetCount = current.events.length;
  if (
    bytes >= EXFIL_BYTES_THRESHOLD &&
    packetCount >= EXFIL_PACKET_THRESHOLD &&
    now - current.lastAlertAt >= ALERT_COOLDOWN_MS
  ) {
    pushAlert(
      "high",
      t("alert.exfil.title"),
      t("alert.exfil.detail", {
        source: packet.source,
        destination: packet.destination,
        bytes,
        seconds: Math.round(EXFIL_WINDOW_MS / 1000),
        packets: packetCount,
      }),
    );
    current.lastAlertAt = now;
  }

  state.exfilState.set(key, current);
}

export function analyzePacketForAlerts(packet) {
  const proto = String(packet.protocol || "").toUpperCase();
  const flags = parseTcpFlags(packet.tcp_flags);
  const isSynOnly = proto === "TCP" && flags.has("SYN") && !flags.has("ACK");

  const now = Date.now();
  if (isSynOnly) {
    maybeDetectSynScan(packet, now);
    maybeDetectBruteforce(packet, now);
  }

  maybeDetectBeaconing(packet, now);
  maybeDetectExfilBurst(packet, now);
}

export function maybeDetectTrafficSpike(latestPps, latestBps) {
  if (!state.rules.exfil) {
    return;
  }

  const now = Date.now();
  const baselinePoints = state.ppsHistory.slice(-TRAFFIC_SPIKE_WINDOW_POINTS);
  const baseline =
    baselinePoints.length === 0
      ? 0
      : baselinePoints.reduce((sum, value) => sum + value, 0) / baselinePoints.length;
  const threshold = Math.max(120, Math.round(baseline * 3.5));

  if (latestPps >= threshold && latestPps >= 60 && now - state.trafficSpikeLastAlertAt >= ALERT_COOLDOWN_MS) {
    pushAlert(
      "low",
      t("alert.spike.title"),
      t("alert.spike.detail", { pps: latestPps, bps: latestBps, threshold }),
    );
    state.trafficSpikeLastAlertAt = now;
  }
}
