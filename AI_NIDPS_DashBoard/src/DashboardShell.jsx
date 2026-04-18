import { useEffect, useMemo, useRef, useState } from "react";

import { API_BASE, adminFetch, buildRequestHeaders } from "./api";
import OnlineLearningPage from "./OnlineLearningPage";
import OverviewPage from "./OverviewPage";
import ShadowReportPage from "./ShadowReportPage";

const defaultModelOverview = {
  summaryStatus: "Unknown",
  current: {
    name: "Current Production Model",
    engine: "XGBoost",
    mode: "production",
    status: "Unknown",
    participatesInBlock: true,
    eventScoring: "-",
    note: "-",
    lastUpdated: null,
    attackModel: { name: "-", exists: false, updatedAt: null },
    malwareModel: { name: "-", exists: false, updatedAt: null },
  },
  shadow: {
    name: "Shadow Online Model",
    engine: "River",
    mode: "shadow",
    status: "Unknown",
    participatesInBlock: false,
    eventScoring: "-",
    note: "-",
    lastUpdated: null,
    attackModel: { name: "-", exists: false, updatedAt: null },
    malwareModel: { name: "-", exists: false, updatedAt: null },
    canPromote: false,
  },
  learning: {
    totalSamples: 0,
    pendingLabels: 0,
    reviewCandidates: 0,
    readyForTraining: 0,
    readyWeight: 0,
    trainedSamples: 0,
    storePath: "-",
    shadowCaptureEnabled: true,
    autoTrainEnabled: true,
    liveDecisionSource: "production",
    lastDecisionSourceSwitchAt: null,
    autoTrainMinWeight: 24,
    autoTrainBatchWeight: 36,
    autoTrainMaxBatchSamples: 4,
    autoTrainMinBatchSamples: 3,
    autoCheckpointMinTrain: 50,
    autoCheckpointMinWeight: 24,
    shadowEvalMinReferenceSamples: 8,
    lastAutoTrainAt: null,
    lastAutoTrainCount: 0,
    lastAutoTrainWeight: 0,
    lastShadowEvalAt: null,
    lastShadowEvalStatus: null,
    lastShadowEvalReason: null,
    lastShadowEvalReferenceSamples: 0,
    lastShadowEvalBatchSamples: 0,
    lastShadowEvalMetrics: {},
    lastCheckpointAt: null,
    lastCheckpointDir: null,
    lastRollbackAt: null,
    lastRollbackDir: null,
    lastRollbackReason: null,
  },
};

const REQUEST_TIMEOUT_MS = 4000;
const OVERVIEW_POLL_MS = 2000;
const LIVE_ALERTS_POLL_MS = 900;
const ONLINE_LEARNING_POLL_MS = 3000;
const SHADOW_REPORT_POLL_MS = 4500;
const ROUTER_STATUS_POLL_MS = 5000;
const RUNTIME_METRICS_POLL_MS = 1000;
const HONEYPOT_LOG_POLL_MS = 1500;
const HIGH_VALUE_HONEYPOT_EVENTS = new Set([
  "cowrie.login.success",
  "cowrie.login.failed",
  "cowrie.command.input",
  "cowrie.session.file_download",
  "cowrie.session.file_upload",
  "cowrie.direct-tcpip.request",
]);

const defaultRouterStatus = {
  routerIp: "-",
  configured: false,
  reachable: false,
  identity: null,
  version: null,
  uptime: null,
  architecture: null,
  cpuLoad: null,
  memoryUsagePercent: null,
  totalMemoryMb: null,
  freeMemoryMb: null,
  usedMemoryMb: null,
  packetsParsed: 0,
  flowRecords: 0,
  metricsWindowEvents: 0,
  blockedCount: 0,
  blockedIps: [],
  status: "Unknown",
  error: null,
};

const defaultRuntimeMetrics = {
  packetsParsed: 0,
  flowRecords: 0,
  activeAggregates: 0,
  runtimeMetricsUpdatedAt: null,
  metricsWindowEvents: 0,
  windowSeconds: 30,
};

const defaultManualResponseSummary = {
  active: 0,
  honeypot: 0,
  totalOpen: 0,
};

async function fetchJson(endpoint, fallback) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      signal: controller.signal,
      cache: "no-store",
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.warn(`Dashboard request failed for ${endpoint}:`, error);
    return fallback;
  } finally {
    clearTimeout(timeoutId);
  }
}

function getInitialPage() {
  if (typeof window === "undefined") return "overview";
  if (window.location.hash === "#/online-learning") return "online-learning";
  if (window.location.hash === "#/shadow-report") return "shadow-report";
  return "overview";
}

export default function DashboardShell() {
  const [page, setPage] = useState(getInitialPage);
  const [stats, setStats] = useState({
    liveAlerts: 0,
    blockedIps: 0,
    honeypotRedirects: 0,
    modelStatus: "Unknown",
    threatOverviewItems: [],
    threatOverviewTotal: 0,
  });
  const [modelOverview, setModelOverview] = useState(defaultModelOverview);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [manualResponse, setManualResponse] = useState([]);
  const [manualResponseSummary, setManualResponseSummary] = useState(defaultManualResponseSummary);
  const [timeline, setTimeline] = useState([]);
  const [routerStatus, setRouterStatus] = useState(defaultRouterStatus);
  const [runtimeMetrics, setRuntimeMetrics] = useState(defaultRuntimeMetrics);
  const [selectedLogIp, setSelectedLogIp] = useState("");
  const [selectedLogMode, setSelectedLogMode] = useState("events");
  const [logItems, setLogItems] = useState([]);
  const [logModalOpen, setLogModalOpen] = useState(false);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [logError, setLogError] = useState("");
  const [showRawHoneypotLogs, setShowRawHoneypotLogs] = useState(false);
  const [pendingSamples, setPendingSamples] = useState([]);
  const [candidateSamples, setCandidateSamples] = useState([]);
  const [readySamples, setReadySamples] = useState([]);
  const [trainedSamples, setTrainedSamples] = useState([]);
  const [actionMessage, setActionMessage] = useState("");
  const fetchDataRef = useRef(async () => {});
  const fetchLiveAlertsRef = useRef(async () => {});
  const loadHoneypotLogsRef = useRef(async () => {});
  const overviewFetchInFlight = useRef(false);
  const overviewFetchQueued = useRef(false);
  const liveAlertsFetchInFlight = useRef(false);
  const liveAlertsFetchQueued = useRef(false);
  const learningFetchInFlight = useRef(false);
  const reportFetchInFlight = useRef(false);
  const routerFetchInFlight = useRef(false);
  const metricsFetchInFlight = useRef(false);
  const honeypotLogsFetchInFlight = useRef(false);

  const architectureNodes = [
    { title: "Home / School WiFi", sub: "Upstream network" },
    { title: "TP-Link WR902AC", sub: "Client Mode bridge" },
    { title: "MikroTik Router", sub: "Flow exporter + enforcement" },
    { title: "Python AI-NIDPS Host", sub: "Detection engine" },
    { title: "VMs / Honeypot", sub: "Clients, attacker, decoy" },
  ];

  const visibleLogItems = useMemo(() => {
    if (selectedLogMode !== "honeypot" || showRawHoneypotLogs) {
      return logItems;
    }
    return logItems.filter((item) => HIGH_VALUE_HONEYPOT_EVENTS.has(String(item.eventid || "").toLowerCase()));
  }, [logItems, selectedLogMode, showRawHoneypotLogs]);

  const fetchOverviewData = async ({ force = false } = {}) => {
    if (overviewFetchInFlight.current) {
      if (force) {
        overviewFetchQueued.current = true;
      }
      return;
    }
    overviewFetchInFlight.current = true;
    try {
    const [nextStats, nextManualPayload, nextTimeline, nextModel] = await Promise.all([
      fetchJson("/stats", stats),
      fetchJson("/manual-response", { items: manualResponse, counts: manualResponseSummary }),
      fetchJson("/timeline", timeline),
      fetchJson("/model-overview", modelOverview),
    ]);

    const nextManualItems = Array.isArray(nextManualPayload)
      ? nextManualPayload
      : Array.isArray(nextManualPayload?.items)
        ? nextManualPayload.items
        : manualResponse;
    const nextManualCounts = Array.isArray(nextManualPayload)
      ? {
          active: nextManualPayload.filter((item) => String(item?.status || "") === "Active").length,
          honeypot: nextManualPayload.filter((item) => String(item?.status || "") === "Honeypot").length,
          totalOpen: nextManualPayload.length,
        }
      : {
          active: Number(nextManualPayload?.counts?.active ?? nextStats?.blockedIps ?? 0),
          honeypot: Number(nextManualPayload?.counts?.honeypot ?? nextStats?.honeypotRedirects ?? 0),
          totalOpen: Number(nextManualPayload?.counts?.totalOpen ?? nextManualItems.length ?? 0),
        };

    setStats(nextStats);
    setManualResponse(nextManualItems);
    setManualResponseSummary(nextManualCounts);
    setTimeline(nextTimeline);
    setModelOverview(nextModel);
    } finally {
      overviewFetchInFlight.current = false;
      if (overviewFetchQueued.current) {
        overviewFetchQueued.current = false;
        void fetchOverviewData();
      }
    }
  };

  const fetchLiveAlertsData = async () => {
    if (liveAlertsFetchInFlight.current) {
      liveAlertsFetchQueued.current = true;
      return;
    }
    liveAlertsFetchInFlight.current = true;
    try {
      const nextEvents = await fetchJson("/events", liveAlerts);
      setLiveAlerts(nextEvents);
    } finally {
      liveAlertsFetchInFlight.current = false;
      if (liveAlertsFetchQueued.current) {
        liveAlertsFetchQueued.current = false;
        void fetchLiveAlertsData();
      }
    }
  };
  fetchLiveAlertsRef.current = fetchLiveAlertsData;

  const fetchLearningData = async ({ includePending }) => {
    if (learningFetchInFlight.current) return;
    learningFetchInFlight.current = true;
    try {
    const requests = [
      fetchJson("/model-overview", modelOverview),
      includePending ? fetchJson("/online-samples?status=pending&limit=8", pendingSamples) : Promise.resolve(pendingSamples),
      includePending ? fetchJson("/online-samples?status=candidate&limit=12", candidateSamples) : Promise.resolve(candidateSamples),
      fetchJson("/online-samples?status=ready&limit=20", readySamples),
      fetchJson("/online-samples?status=trained&limit=80", trainedSamples),
    ];
    const [nextModel, nextPending, nextCandidate, nextReady, nextTrained] = await Promise.all(requests);

    setModelOverview(nextModel);
    if (includePending) {
      setPendingSamples(nextPending);
      setCandidateSamples(nextCandidate);
    }
    setReadySamples(nextReady);
    setTrainedSamples(nextTrained);
    } finally {
      learningFetchInFlight.current = false;
    }
  };

  const fetchShadowReportData = async () => {
    if (reportFetchInFlight.current) return;
    reportFetchInFlight.current = true;
    try {
    const [nextReady, nextTrained] = await Promise.all([
      fetchJson("/online-samples?status=ready&limit=20", readySamples),
      fetchJson("/online-samples?status=trained&limit=80", trainedSamples),
    ]);

    setReadySamples(nextReady);
    setTrainedSamples(nextTrained);
    } finally {
      reportFetchInFlight.current = false;
    }
  };

  const fetchData = async (targetPage = page, options = {}) => {
    if (targetPage === "overview") {
      await fetchOverviewData(options);
      return;
    }
    if (targetPage === "shadow-report") {
      await fetchShadowReportData();
      return;
    }
    await fetchLearningData({ includePending: true });
  };
  fetchDataRef.current = fetchData;

  useEffect(() => {
    const pollMs =
      page === "overview"
        ? OVERVIEW_POLL_MS
        : page === "shadow-report"
          ? SHADOW_REPORT_POLL_MS
          : ONLINE_LEARNING_POLL_MS;
    void fetchDataRef.current(page);
    const interval = setInterval(() => {
      void fetchDataRef.current(page);
    }, pollMs);
    return () => clearInterval(interval);
  }, [page]);

  useEffect(() => {
    if (page !== "overview") return undefined;
    void fetchLiveAlertsRef.current();
    const interval = setInterval(() => {
      void fetchLiveAlertsRef.current();
    }, LIVE_ALERTS_POLL_MS);
    return () => clearInterval(interval);
  }, [page]);

  useEffect(() => {
    if (page !== "overview") return undefined;
    const refreshRouterStatus = async () => {
      if (routerFetchInFlight.current) return;
      routerFetchInFlight.current = true;
      try {
      const nextRouter = await fetchJson("/router-status", null);
      if (!nextRouter) return;
      setRouterStatus((prev) => ({ ...prev, ...nextRouter }));
      } finally {
        routerFetchInFlight.current = false;
      }
    };
    refreshRouterStatus();
    const interval = setInterval(refreshRouterStatus, ROUTER_STATUS_POLL_MS);
    return () => clearInterval(interval);
  }, [page]);

  useEffect(() => {
    if (page !== "overview") return undefined;
    const refreshRuntimeMetrics = async () => {
      if (metricsFetchInFlight.current) return;
      metricsFetchInFlight.current = true;
      try {
      const nextMetrics = await fetchJson("/runtime-metrics", null);
      if (!nextMetrics) return;
      setRuntimeMetrics((prev) => ({ ...prev, ...nextMetrics }));
      } finally {
        metricsFetchInFlight.current = false;
      }
    };
    refreshRuntimeMetrics();
    const interval = setInterval(refreshRuntimeMetrics, RUNTIME_METRICS_POLL_MS);
    return () => clearInterval(interval);
  }, [page]);

  useEffect(() => {
    if (!actionMessage) return undefined;
    const timeoutId = setTimeout(() => setActionMessage(""), 4500);
    return () => clearTimeout(timeoutId);
  }, [actionMessage]);

  useEffect(() => {
    if (typeof document === "undefined") return undefined;
    const previousOverflow = document.body.style.overflow;
    const previousOverscrollBehavior = document.body.style.overscrollBehavior;
    if (logModalOpen) {
      document.body.style.overflow = "hidden";
      document.body.style.overscrollBehavior = "contain";
    }
    return () => {
      document.body.style.overflow = previousOverflow;
      document.body.style.overscrollBehavior = previousOverscrollBehavior;
    };
  }, [logModalOpen]);

  useEffect(() => {
    const syncPage = () => {
      setPage(getInitialPage());
      setActionMessage("");
    };
    window.addEventListener("hashchange", syncPage);
    return () => window.removeEventListener("hashchange", syncPage);
  }, []);

  useEffect(() => {
    if (!logModalOpen || selectedLogMode !== "honeypot" || !selectedLogIp) return undefined;
    const interval = setInterval(() => {
      void loadHoneypotLogsRef.current(selectedLogIp, { silent: true });
    }, HONEYPOT_LOG_POLL_MS);
    return () => clearInterval(interval);
  }, [logModalOpen, selectedLogMode, selectedLogIp]);

  const navigateTo = (nextPage) => {
    setActionMessage("");
    const nextHash =
      nextPage === "online-learning"
        ? "#/online-learning"
        : nextPage === "shadow-report"
          ? "#/shadow-report"
          : "#/";
    if (window.location.hash !== nextHash) {
      window.location.hash = nextHash;
    } else {
      setPage(nextPage);
    }
  };

  const scoreText = (value) => {
    if (value === null || value === undefined || value === "") return "-";
    const num = Number(value);
    return Number.isFinite(num) ? num.toFixed(2) : "-";
  };

  const getReadableRule = (rule) => {
    const normalized = String(rule || "").toUpperCase();
    if (normalized === "OBS_UNKNOWN") return "Unknown Traffic";
    return String(rule || "")
      .replaceAll("_", " ")
      .toLowerCase()
      .replace(/\b\w/g, (c) => c.toUpperCase());
  };

  const getEventTitle = (item) => item.display_label || getReadableRule(item.rule);
  const familyText = (sample) => sample.display_label || sample.family_label || "Unassigned";

  const getSeverity = (alert) => {
    const rule = String(alert.rule || "").toUpperCase();
    const atk = Number(alert.atk || 0);
    const mal = Number(alert.mal || 0);
    const decision = String(alert.decision || "").toUpperCase();

    if (rule === "OBS_UNKNOWN") return "Unknown";
    if (rule.includes("C2") || mal >= 0.8 || decision.includes("HONEYPOT")) return "Critical";
    if (atk >= 0.7 || decision.startsWith("BLOCKED")) return "High";
    if (decision === "OBSERVED") return "Observed";
    return "Medium";
  };

  const getSeverityColor = (severity) => {
    if (severity === "Critical") return "#ef4444";
    if (severity === "High") return "#f97316";
    if (severity === "Observed") return "#22c55e";
    if (severity === "Unknown") return "#67e8f9";
    return "#eab308";
  };

  const getActionText = (decision) => {
    const d = String(decision || "").toUpperCase();
    if (d.startsWith("BLOCKED")) return "Blocked";
    if (d.includes("HONEYPOT")) return "Redirected to Honeypot";
    if (d.includes("FAILED")) return "Failed";
    if (d === "ALREADY_BLOCKED_OR_NEVER") return "Already Blocked";
    if (d === "SUPPRESSED_VICTIM_LEG") return "Suppressed";
    if (d === "OBSERVED") return "Observed";
    return "Alert Only";
  };

  const getActionColor = (action) => {
    if (action === "Blocked") return "#fca5a5";
    if (action === "Redirected to Honeypot") return "#c084fc";
    if (action === "Failed") return "#f87171";
    if (action === "Already Blocked") return "#fbbf24";
    if (action === "Suppressed") return "#94a3b8";
    if (action === "Observed") return "#86efac";
    return "#67e8f9";
  };

  const getStatusColor = (status) => {
    if (status === "Honeypot") return "#c084fc";
    if (status === "Review") return "#67e8f9";
    if (status === "Observed") return "#86efac";
    return "#cbd5e1";
  };

  const getTimelineColor = (state) => {
    if (state === "blocked") return "#ef4444";
    if (state === "honeypot") return "#a855f7";
    if (state === "observed") return "#22c55e";
    return "#22d3ee";
  };

  const getModelStatusColor = (status) => {
    const normalized = String(status || "").toLowerCase();
    if (normalized.includes("ready")) return { border: "#22c55e", text: "#86efac" };
    if (normalized.includes("missing")) return { border: "#ef4444", text: "#fca5a5" };
    return { border: "#fbbf24", text: "#fde68a" };
  };

  const getEvalStatusColor = (status) => {
    const normalized = String(status || "").toLowerCase();
    if (normalized.includes("accept")) return "#86efac";
    if (normalized.includes("reject")) return "#fca5a5";
    if (normalized.includes("skip")) return "#fcd34d";
    return "#94a3b8";
  };

  const handleViewLogs = async (ip) => {
    try {
      setLoadingLogs(true);
      setLogError("");
      setShowRawHoneypotLogs(false);
      setSelectedLogMode("events");
      setSelectedLogIp(ip);
      setLogModalOpen(true);
      const res = await fetch(`${API_BASE}/logs?ip=${encodeURIComponent(ip)}`);
      const data = await res.json();
      setLogItems(data);
    } catch (error) {
      console.error("Failed to load logs:", error);
      setLogError(error.message || "Failed to load logs.");
      setLogItems([]);
    } finally {
      setLoadingLogs(false);
    }
  };

  const loadHoneypotLogs = async (ip, { silent = false } = {}) => {
    if (!ip || honeypotLogsFetchInFlight.current) return;
    honeypotLogsFetchInFlight.current = true;
    try {
      if (!silent) {
        setLoadingLogs(true);
        setLogError("");
      }
      const res = await adminFetch(`/honeypot-logs?ip=${encodeURIComponent(ip)}`, {
        cache: "no-store",
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Failed to load honeypot logs.");
      }
      setLogItems(Array.isArray(data.items) ? data.items : []);
    } catch (error) {
      if (silent) {
        console.warn("Failed to refresh honeypot logs:", error);
      } else {
        console.error("Failed to load honeypot logs:", error);
        setLogError(error.message || "Failed to load honeypot logs.");
        setLogItems([]);
      }
    } finally {
      if (!silent) {
        setLoadingLogs(false);
      }
      honeypotLogsFetchInFlight.current = false;
    }
  };

  const handleViewHoneypotLogs = async (ip) => {
    setShowRawHoneypotLogs(false);
    setSelectedLogMode("honeypot");
    setSelectedLogIp(ip);
    setLogModalOpen(true);
    await loadHoneypotLogs(ip);
  };
  loadHoneypotLogsRef.current = loadHoneypotLogs;

  const handleUnblock = async (ip) => {
    try {
      setActionMessage("");
      const res = await adminFetch("/unblock", {
        method: "POST",
        headers: buildRequestHeaders({ json: true }),
        body: JSON.stringify({ ip }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setActionMessage(`Unblock failed: ${data.error || "Unknown error"}`);
        return;
      }
      const existingCard = manualResponse.find((card) => card.ip === ip);
      setManualResponse((prev) => prev.filter((card) => card.ip !== ip));
      setStats((prev) => ({
        ...prev,
        blockedIps:
          existingCard?.status === "Active"
            ? Math.max(0, Number(prev.blockedIps || 0) - 1)
            : prev.blockedIps,
        honeypotRedirects:
          existingCard?.status === "Honeypot"
            ? Math.max(0, Number(prev.honeypotRedirects || 0) - 1)
            : prev.honeypotRedirects,
      }));
      setRouterStatus((prev) => {
        const nextBlockedIps = Array.isArray(prev.blockedIps)
          ? prev.blockedIps.filter((address) => String(address) !== ip)
          : [];
        const nextHoneypotIps = Array.isArray(prev.honeypotIps)
          ? prev.honeypotIps.filter((address) => String(address) !== ip)
          : [];
        return {
          ...prev,
          blockedIps: nextBlockedIps,
          blockedCount: nextBlockedIps.length,
          honeypotIps: nextHoneypotIps,
          honeypotCount: nextHoneypotIps.length,
        };
      });
      setActionMessage(`Unblocked ${ip} successfully.`);
      await Promise.all([
        fetchData(page, { force: true }),
        page === "overview" ? fetchLiveAlertsData() : Promise.resolve(),
      ]);
    } catch (error) {
      setActionMessage(`Unblock failed: ${error.message}`);
    }
  };

  const handleShadowCaptureToggle = async (enabled) => {
    try {
      setActionMessage("");
      const res = await adminFetch("/shadow-capture", {
        method: "POST",
        headers: buildRequestHeaders({ json: true }),
        body: JSON.stringify({ enabled }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setActionMessage(`Shadow capture update failed: ${data.error || "Unknown error"}`);
        return;
      }
      setActionMessage(enabled ? "Shadow capture resumed." : "Shadow capture paused.");
      await fetchData();
    } catch (error) {
      setActionMessage(`Shadow capture update failed: ${error.message}`);
    }
  };

  const handleAutoTrainToggle = async (enabled) => {
    try {
      setActionMessage("");
      const res = await adminFetch("/shadow-auto-train", {
        method: "POST",
        headers: buildRequestHeaders({ json: true }),
        body: JSON.stringify({ enabled }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setActionMessage(`Auto-train update failed: ${data.error || "Unknown error"}`);
        return;
      }
      setActionMessage(enabled ? "Shadow auto-train resumed." : "Shadow auto-train paused.");
      await fetchData();
    } catch (error) {
      setActionMessage(`Auto-train update failed: ${error.message}`);
    }
  };

  const handleManualOnlineLabel = async (sample, attack, malware) => {
    try {
      setActionMessage("");
      const eventIds = Array.isArray(sample?.cluster_event_ids) && sample.cluster_event_ids.length
        ? sample.cluster_event_ids
        : sample?.event_id
          ? [sample.event_id]
          : [];
      const res = await adminFetch("/online-label", {
        method: "POST",
        headers: buildRequestHeaders({ json: true }),
        body: JSON.stringify({
          event_id: eventIds[0],
          event_ids: eventIds,
          attack,
          malware,
          source: "manual_dashboard",
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setActionMessage(`Label update failed: ${data.error || "Unknown error"}`);
        return;
      }
      const labelText =
        attack === 0 && malware === 0
          ? "benign"
          : attack === 1 && malware === 0
            ? "attack"
            : attack === 0 && malware === 1
              ? "malware"
              : `attack=${attack} malware=${malware}`;
      const updatedCount = Number(data?.updated || eventIds.length || 1);
      if (updatedCount > 1) {
        setActionMessage(`Marked ${updatedCount} similar review samples as ${labelText}.`);
      } else {
        setActionMessage(`Marked ${sample?.rule || sample?.event_id || "sample"} as ${labelText}.`);
      }
      await fetchData();
    } catch (error) {
      setActionMessage(`Label update failed: ${error.message}`);
    }
  };

  const handleRollbackShadow = async () => {
    try {
      setActionMessage("");
      const res = await adminFetch("/shadow-rollback", {
        method: "POST",
        headers: buildRequestHeaders({ json: true }),
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setActionMessage(`Rollback failed: ${data.error || "Unknown error"}`);
        return;
      }
      setActionMessage(`Rollback completed: ${data.rollback.checkpointDir}`);
      await fetchData();
    } catch (error) {
      setActionMessage(`Rollback failed: ${error.message}`);
    }
  };

  const handleLiveDecisionSourceChange = async (source) => {
    try {
      setActionMessage("");
      const res = await adminFetch("/live-decision-source", {
        method: "POST",
        headers: buildRequestHeaders({ json: true }),
        body: JSON.stringify({ source }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setActionMessage(`Model switch failed: ${data.error || "Unknown error"}`);
        return;
      }
      setActionMessage(source === "shadow" ? "Live decisions now use the online shadow model." : "Live decisions switched back to the production model.");
      await fetchData();
    } catch (error) {
      setActionMessage(`Model switch failed: ${error.message}`);
    }
  };

  const summaryCards = [
    { label: "Live Alerts", value: stats.liveAlerts, note: "Cumulative monitor events" },
    { label: "Blocked IPs", value: stats.blockedIps, note: "Currently blocked sources" },
    { label: "Honeypot Redirects", value: stats.honeypotRedirects, note: "Suspicious redirected sources" },
    { label: "Model Status", value: stats.modelStatus, note: `Live source: ${modelOverview.learning.liveDecisionSource === "shadow" ? "Online Shadow" : "Production"}` },
  ];

  const learningStats = [
    { label: "Online Samples", value: modelOverview.learning.totalSamples },
    { label: "Pending Labels", value: modelOverview.learning.pendingLabels },
    { label: "Review Candidates", value: modelOverview.learning.reviewCandidates },
    { label: "Ready To Train", value: modelOverview.learning.readyForTraining },
    { label: "Ready Capacity", value: scoreText(modelOverview.learning.readyWeight) },
  ];

  const shadowReport = useMemo(() => {
    const reportSamples = [...readySamples, ...trainedSamples];

    const buildSection = (bucket, currentKey, shadowKey) => {
      const groups = new Map();
      reportSamples.forEach((sample) => {
        const family = String(sample.family_label || "");
        const category = String(sample.category || "").toUpperCase();
        const isAttack = family.startsWith("attack.") || category === "ATTACK";
        const isMalware = family.startsWith("malware.") || category === "MALWARE";
        if ((bucket === "attack" && !isAttack) || (bucket === "malware" && !isMalware)) return;

        const currentFallbackKey =
          currentKey === "current_attack_score"
            ? "xgb_attack_score"
            : currentKey === "current_malware_score"
              ? "xgb_malware_score"
              : currentKey;
        const currentScore = Number(
          sample[currentKey] ?? sample[currentFallbackKey]
        );
        const shadowScore = Number(
          sample[
            shadowKey === "online_attack_score"
              ? "display_latest_online_attack_score"
              : shadowKey === "online_malware_score"
                ? "display_latest_online_malware_score"
                : shadowKey
          ] ??
          sample[
            shadowKey === "online_attack_score"
              ? "latest_online_attack_score"
              : shadowKey === "online_malware_score"
                ? "latest_online_malware_score"
                : shadowKey
          ]
        );
        if (!Number.isFinite(currentScore) && !Number.isFinite(shadowScore)) return;
        const key = sample.family_label || sample.rule || "unknown";
        const current = groups.get(key) || {
          key,
          title: sample.display_label || getReadableRule(sample.rule),
          family: sample.family_label || "-",
          latestTs: sample.ts,
          sampleCount: 0,
          readyCount: 0,
          trainedCount: 0,
          currentTotal: 0,
          currentCount: 0,
          currentMax: 0,
          shadowTotal: 0,
          shadowCount: 0,
          shadowMax: 0,
          trainAttemptCount: 0,
          rejectCount: 0,
          latestTrainAttemptAt: null,
          latestRejectedAt: null,
          trainedSeen: false,
          readySeen: false,
        };
        current.sampleCount += 1;
        if (Number.isFinite(currentScore)) {
          current.currentTotal += currentScore;
          current.currentCount += 1;
          current.currentMax = Math.max(current.currentMax, currentScore);
        }
        if (Number.isFinite(shadowScore)) {
          current.shadowTotal += shadowScore;
          current.shadowCount += 1;
          current.shadowMax = Math.max(current.shadowMax, shadowScore);
        }
        if (String(sample.ts || "") > String(current.latestTs || "")) current.latestTs = sample.ts;
        current.trainAttemptCount += Number(sample.train_attempt_count || 0);
        current.rejectCount += Number(sample.reject_count || 0);
        if (String(sample.last_train_attempt_at || "") > String(current.latestTrainAttemptAt || "")) {
          current.latestTrainAttemptAt = sample.last_train_attempt_at;
        }
        if (String(sample.last_rejected_at || "") > String(current.latestRejectedAt || "")) {
          current.latestRejectedAt = sample.last_rejected_at;
        }
        if (sample.trained) {
          current.trainedSeen = true;
          current.trainedCount += 1;
        } else {
          current.readySeen = true;
          current.readyCount += 1;
        }
        groups.set(key, current);
      });
      return Array.from(groups.values())
        .map((item) => {
          const currentAvg = item.currentCount > 0 ? item.currentTotal / item.currentCount : 0;
          const shadowAvg = item.shadowCount > 0 ? item.shadowTotal / item.shadowCount : 0;
          return {
            ...item,
            currentAvg,
            shadowAvg,
            delta: shadowAvg - currentAvg,
          };
        })
        .sort((a, b) => Math.max(b.shadowMax, b.currentMax) - Math.max(a.shadowMax, a.currentMax));
    };

    return {
      source: {
        trained: trainedSamples.length,
        ready: readySamples.length,
      },
      attack: buildSection("attack", "current_attack_score", "online_attack_score"),
      malware: buildSection("malware", "current_malware_score", "online_malware_score"),
    };
  }, [readySamples, trainedSamples]);

  const helpers = {
    scoreText,
    getReadableRule,
    getEventTitle,
    familyText,
    getSeverity,
    getSeverityColor,
    getActionText,
    getActionColor,
    getStatusColor,
    getTimelineColor,
    getModelStatusColor,
    getEvalStatusColor,
  };

  const navButtonStyle = (active) => ({
    background: active ? "rgba(34, 211, 238, 0.14)" : "rgba(255,255,255,0.03)",
    color: active ? "#67e8f9" : "#cbd5e1",
    border: `1px solid ${active ? "#0891b2" : "#334155"}`,
    borderRadius: "999px",
    padding: "10px 16px",
    cursor: "pointer",
    fontWeight: "600",
  });

  const buttonStyle = {
    background: "rgba(255,255,255,0.04)",
    color: "#e2e8f0",
    border: "1px solid #334155",
    borderRadius: "10px",
    padding: "10px 14px",
    cursor: "pointer",
  };

  return (
    <div
      style={{
        padding: "20px",
        background: "#0f172a",
        minHeight: "100vh",
        color: "white",
        boxSizing: "border-box",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", gap: "16px", marginBottom: "18px", flexWrap: "wrap" }}>
        <div>
          <h1 style={{ fontSize: "42px", marginBottom: "12px", marginTop: 0 }}>AI-NIDPS Monitoring Dashboard</h1>
          <p style={{ fontSize: "16px", marginBottom: 0, color: "#cbd5e1", maxWidth: "960px" }}>
            AI-powered network intrusion detection with real-time monitoring and adaptive defense.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
          <button onClick={() => navigateTo("overview")} style={navButtonStyle(page === "overview")}>
            Main Dashboard
          </button>
          <button onClick={() => navigateTo("online-learning")} style={navButtonStyle(page === "online-learning")}>
            Online Learning
          </button>
        </div>
      </div>

      {page === "overview" ? (
        <OverviewPage
          summaryCards={summaryCards}
          liveAlerts={liveAlerts}
          threatOverviewItems={stats.threatOverviewItems}
          threatOverviewTotal={stats.threatOverviewTotal}
          manualResponse={manualResponse}
          manualResponseSummary={manualResponseSummary}
          timeline={timeline}
          architectureNodes={architectureNodes}
          routerStatus={routerStatus}
          runtimeMetrics={runtimeMetrics}
          actionMessage={actionMessage}
          onViewLogs={handleViewLogs}
          onViewHoneypotLogs={handleViewHoneypotLogs}
          onUnblock={handleUnblock}
          helpers={helpers}
        />
      ) : page === "shadow-report" ? (
        <ShadowReportPage
          shadowReport={shadowReport}
          helpers={helpers}
          onOpenOnlineLearning={() => navigateTo("online-learning")}
        />
      ) : (
        <OnlineLearningPage
          modelOverview={modelOverview}
          learningStats={learningStats}
          pendingSamples={pendingSamples}
          candidateSamples={candidateSamples}
          readySamples={readySamples}
          actionMessage={actionMessage}
          onShadowCaptureToggle={handleShadowCaptureToggle}
          onAutoTrainToggle={handleAutoTrainToggle}
          onManualLabel={handleManualOnlineLabel}
          onRollbackShadow={handleRollbackShadow}
          onLiveDecisionSourceChange={handleLiveDecisionSourceChange}
          onOpenReport={() => navigateTo("shadow-report")}
          helpers={helpers}
        />
      )}

      {logModalOpen && (
        <div
          onClick={() => setLogModalOpen(false)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(2, 6, 23, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: "20px",
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: "100%",
              maxWidth: "1100px",
              maxHeight: "85vh",
              background: "#0f172a",
              border: "1px solid #334155",
              borderRadius: "16px",
              overflow: "hidden",
              display: "flex",
              flexDirection: "column",
            }}
          >
            <div
              style={{
                padding: "16px 20px",
                borderBottom: "1px solid #334155",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div>
                <div style={{ fontSize: "18px", fontWeight: "700" }}>
                  {selectedLogMode === "honeypot" ? `Honeypot Logs for ${selectedLogIp}` : `Logs for ${selectedLogIp}`}
                </div>
                <div style={{ color: "#94a3b8", fontSize: "13px", marginTop: "4px" }}>
                  {selectedLogMode === "honeypot"
                    ? showRawHoneypotLogs
                      ? "Raw Cowrie events involving this source IP"
                      : "High-value Cowrie events involving this source IP"
                    : "Recent events involving this IP"}
                </div>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                {selectedLogMode === "honeypot" && (
                  <button
                    onClick={() => setShowRawHoneypotLogs((prev) => !prev)}
                    style={{
                      ...buttonStyle,
                      borderColor: showRawHoneypotLogs ? "#a855f7" : "#334155",
                      color: showRawHoneypotLogs ? "#e9d5ff" : "#cbd5e1",
                    }}
                  >
                    {showRawHoneypotLogs ? "Show High-Value Events" : "Show Raw Events"}
                  </button>
                )}
                <button onClick={() => setLogModalOpen(false)} style={buttonStyle}>
                  Close
                </button>
              </div>
            </div>

            <div style={{ padding: "16px 20px", overflow: "auto" }}>
              {loadingLogs ? (
                <div style={{ color: "#94a3b8" }}>Loading logs...</div>
              ) : logError ? (
                <div style={{ color: "#fca5a5" }}>{logError}</div>
              ) : visibleLogItems.length === 0 ? (
                <div style={{ color: "#94a3b8" }}>
                  {selectedLogMode === "honeypot" && !showRawHoneypotLogs
                    ? "No high-value honeypot events yet. Switch to raw events to inspect the full Cowrie stream."
                    : "No logs found for this IP."}
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    {selectedLogMode === "honeypot" ? (
                      <tr style={{ textAlign: "left", borderBottom: "1px solid #334155", color: "#94a3b8" }}>
                        <th style={{ padding: "12px" }}>Time</th>
                        <th style={{ padding: "12px" }}>Event</th>
                        <th style={{ padding: "12px" }}>Source</th>
                        <th style={{ padding: "12px" }}>Username</th>
                        <th style={{ padding: "12px" }}>Password</th>
                        <th style={{ padding: "12px" }}>Input</th>
                        <th style={{ padding: "12px" }}>Details</th>
                      </tr>
                    ) : (
                      <tr style={{ textAlign: "left", borderBottom: "1px solid #334155", color: "#94a3b8" }}>
                        <th style={{ padding: "12px" }}>Time</th>
                        <th style={{ padding: "12px" }}>Rule</th>
                        <th style={{ padding: "12px" }}>Source</th>
                        <th style={{ padding: "12px" }}>Target</th>
                        <th style={{ padding: "12px" }}>Current Attack</th>
                        <th style={{ padding: "12px" }}>Current Malware</th>
                        <th style={{ padding: "12px" }}>Decision</th>
                      </tr>
                    )}
                  </thead>
                  <tbody>
                    {selectedLogMode === "honeypot"
                      ? visibleLogItems.map((item, idx) => (
                          <tr key={idx} style={{ borderBottom: "1px solid #334155" }}>
                            <td style={{ padding: "12px", whiteSpace: "nowrap" }}>{item.ts}</td>
                            <td style={{ padding: "12px" }}>
                              <div>{item.eventid || "-"}</div>
                              {item.session && item.session !== "-" && (
                                <div style={{ color: "#64748b", fontSize: "11px", marginTop: "4px" }}>session {item.session}</div>
                              )}
                            </td>
                            <td style={{ padding: "12px" }}>{item.src || "-"}</td>
                            <td style={{ padding: "12px" }}>{item.username || "-"}</td>
                            <td style={{ padding: "12px", color: "#c084fc" }}>{item.password || "-"}</td>
                            <td style={{ padding: "12px", color: "#67e8f9" }}>{item.input || "-"}</td>
                            <td style={{ padding: "12px" }}>{item.message || "-"}</td>
                          </tr>
                        ))
                      : visibleLogItems.map((item, idx) => (
                          <tr key={idx} style={{ borderBottom: "1px solid #334155" }}>
                            <td style={{ padding: "12px" }}>{item.ts}</td>
                            <td style={{ padding: "12px" }}>
                              <div>{getEventTitle(item)}</div>
                              {item.family_label && (
                                <div style={{ color: "#64748b", fontSize: "11px", marginTop: "4px" }}>{item.family_label}</div>
                              )}
                              {String(item.rule || "").toUpperCase() === "OBS_UNKNOWN" && (
                                <div style={{ color: "#67e8f9", fontSize: "11px", marginTop: "4px" }}>New / Unmatched Pattern</div>
                              )}
                            </td>
                            <td style={{ padding: "12px" }}>{item.src}</td>
                            <td style={{ padding: "12px" }}>{item.dst}</td>
                            <td style={{ padding: "12px", color: "#67e8f9" }}>{scoreText(item.atk)}</td>
                            <td style={{ padding: "12px", color: "#c084fc" }}>{scoreText(item.mal)}</td>
                            <td style={{ padding: "12px" }}>{item.decision}</td>
                          </tr>
                        ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
