import { useEffect, useMemo, useState } from "react";

function parseRouterUptimeToSeconds(rawValue) {
  const text = String(rawValue || "").trim();
  if (!text) return null;

  let total = 0;
  let matched = false;
  const regex = /(\d+)([wdhms])/gi;
  let match;
  while ((match = regex.exec(text)) !== null) {
    matched = true;
    const value = Number(match[1] || 0);
    const unit = String(match[2] || "").toLowerCase();
    if (unit === "w") total += value * 7 * 24 * 3600;
    if (unit === "d") total += value * 24 * 3600;
    if (unit === "h") total += value * 3600;
    if (unit === "m") total += value * 60;
    if (unit === "s") total += value;
  }
  return matched ? total : null;
}

function formatRouterUptime(seconds, fallback) {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) {
    return fallback || "-";
  }

  let remaining = Math.max(0, Math.floor(seconds));
  const weeks = Math.floor(remaining / (7 * 24 * 3600));
  remaining -= weeks * 7 * 24 * 3600;
  const days = Math.floor(remaining / (24 * 3600));
  remaining -= days * 24 * 3600;
  const hours = Math.floor(remaining / 3600);
  remaining -= hours * 3600;
  const minutes = Math.floor(remaining / 60);
  remaining -= minutes * 60;
  const parts = [];
  if (weeks) parts.push(`${weeks}w`);
  if (days) parts.push(`${days}d`);
  if (hours || parts.length) parts.push(`${hours}h`);
  if (minutes || parts.length) parts.push(`${minutes}m`);
  parts.push(`${remaining}s`);
  return parts.join("");
}

function parseDashboardTimestampToEpochSeconds(rawValue) {
  const text = String(rawValue || "").trim();
  if (!text) return null;
  const normalized = text.replace(" ", "T");
  const parsed = Date.parse(normalized);
  if (Number.isNaN(parsed)) return null;
  return Math.floor(parsed / 1000);
}

function formatRelativeAge(epochSeconds, nowEpochSeconds) {
  if (!epochSeconds || !nowEpochSeconds) return "waiting for update";
  const delta = Math.max(0, Math.floor(nowEpochSeconds - epochSeconds));
  if (delta <= 1) return "just now";
  if (delta < 60) return `${delta}s ago`;
  const minutes = Math.floor(delta / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

export default function OverviewPage({
  summaryCards,
  liveAlerts,
  threatOverviewItems,
  threatOverviewTotal,
  manualResponse,
  manualResponseSummary,
  routerStatus,
  runtimeMetrics,
  actionMessage,
  onViewLogs,
  onViewHoneypotLogs,
  onUnblock,
  helpers,
}) {
  const {
    scoreText,
    getEventTitle,
    getSeverity,
    getSeverityColor,
    getActionText,
    getActionColor,
    getStatusColor,
  } = helpers;

  const baseUptimeSeconds = useMemo(() => parseRouterUptimeToSeconds(routerStatus.uptime), [routerStatus.uptime]);
  const routerSnapshotEpoch = useMemo(() => parseDashboardTimestampToEpochSeconds(routerStatus.lastCheckedAt), [routerStatus.lastCheckedAt]);
  const runtimeMetricsEpoch = useMemo(
    () => parseDashboardTimestampToEpochSeconds(runtimeMetrics?.runtimeMetricsUpdatedAt),
    [runtimeMetrics?.runtimeMetricsUpdatedAt]
  );
  const [clockEpochSeconds, setClockEpochSeconds] = useState(() => Math.floor(Date.now() / 1000));

  useEffect(() => {
    const timerId = setInterval(() => {
      setClockEpochSeconds(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => clearInterval(timerId);
  }, []);

  const sectionStyle = {
    background: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '16px',
    padding: '20px',
  };

  const compactButtonStyle = {
    background: 'rgba(255,255,255,0.04)',
    color: '#e2e8f0',
    border: '1px solid #334155',
    borderRadius: '10px',
    padding: '8px 12px',
    cursor: 'pointer',
    fontSize: '12px',
  };

  const getManualResponseStatusTone = (status) => {
    if (status === "Active") {
      return {
        border: "#ef4444",
        text: "#fecaca",
        background: "rgba(239, 68, 68, 0.14)",
      };
    }
    if (status === "Honeypot") {
      return {
        border: "#a855f7",
        text: "#e9d5ff",
        background: "rgba(168, 85, 247, 0.14)",
      };
    }
    if (status === "Review") {
      return {
        border: "#0891b2",
        text: "#67e8f9",
        background: "rgba(34, 211, 238, 0.12)",
      };
    }
    if (status === "Observed") {
      return {
        border: "#22c55e",
        text: "#bbf7d0",
        background: "rgba(34, 197, 94, 0.12)",
      };
    }
    return {
      border: "#334155",
      text: getStatusColor(status),
      background: "transparent",
    };
  };

  const monitorPanelStyle = {
    ...sectionStyle,
    padding: '16px',
    minHeight: '820px',
    maxHeight: '820px',
    display: 'flex',
    flexDirection: 'column',
  };

  const formatCount = (value) => new Intl.NumberFormat().format(Number(value || 0));
  const formatPercent = (value) => {
    if (value === null || value === undefined || value === '') return '-';
    const text = String(value).trim();
    return text.endsWith('%') ? text : `${text}%`;
  };
  const uptimeSeconds =
    baseUptimeSeconds === null
      ? null
      : baseUptimeSeconds + Math.max(0, clockEpochSeconds - (routerSnapshotEpoch ?? clockEpochSeconds));
  const uptimeDisplay = formatRouterUptime(uptimeSeconds, routerStatus.uptime || "-");
  const routerControlAge = formatRelativeAge(routerSnapshotEpoch, clockEpochSeconds);
  const flowMetricsAge = formatRelativeAge(runtimeMetricsEpoch, clockEpochSeconds);
  const flowRecordsRate = Number(runtimeMetrics?.flowRecordsRate ?? 0);
  const flowRecordsTotal = Number(runtimeMetrics?.flowRecords ?? 0);
  const activeAggregates = Number(runtimeMetrics?.activeAggregates ?? 0);
  const firewallEnforcementCount = Number(routerStatus.blockedCount ?? 0) + Number(routerStatus.honeypotCount ?? 0);
  const manualResponseItems = useMemo(() => (Array.isArray(manualResponse) ? manualResponse : []), [manualResponse]);
  const manualResponseOpenCount = Number(manualResponseSummary?.totalOpen ?? manualResponseItems.length ?? 0);
  const cumulativeThreatOverviewItems = useMemo(
    () => (Array.isArray(threatOverviewItems) ? threatOverviewItems : []),
    [threatOverviewItems]
  );
  const cumulativeThreatOverviewTotal = Number(threatOverviewTotal ?? 0);

  const honeypotPanel = useMemo(() => {
    const redirected = liveAlerts.filter((alert) => getActionText(alert.decision) === "Redirected to Honeypot");
    const currentHoneypot = manualResponseItems.find((host) => String(host.status || "").toLowerCase() === "honeypot");
    const latest = redirected[0] || null;
    return {
      currentHoneypot,
      latest,
      recent: redirected.slice(0, 3),
    };
  }, [getActionText, liveAlerts, manualResponseItems]);
  const honeypotLogTargetIp = honeypotPanel.currentHoneypot?.ip || honeypotPanel.latest?.src || "";

  return (
    <>
      {actionMessage && (
        <div
          style={{
            marginBottom: '16px',
            background: 'rgba(34, 211, 238, 0.10)',
            border: '1px solid rgba(34, 211, 238, 0.35)',
            color: '#67e8f9',
            borderRadius: '12px',
            padding: '12px 14px',
          }}
        >
          {actionMessage}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '16px', marginBottom: '24px' }}>
        {summaryCards.map((item) => (
          <div key={item.label} style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '16px' }}>
            <div style={{ fontSize: '14px', color: '#94a3b8' }}>{item.label}</div>
            <div style={{ fontSize: '28px', fontWeight: 'bold', marginTop: '8px' }}>{item.value}</div>
            <div style={{ fontSize: '13px', color: '#22d3ee', marginTop: '6px' }}>{item.note}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2.55fr) minmax(260px, 0.65fr)', gap: '18px', marginBottom: '24px', alignItems: 'stretch' }}>
        <div style={monitorPanelStyle}>
          <h2 style={{ marginTop: 0, marginBottom: '8px' }}>Live Alerts</h2>
          <p style={{ color: '#94a3b8', marginTop: 0, marginBottom: '20px' }}>
            Recent events from the live monitor. This view shows the current live decision scores so you can read monitor actions immediately.
          </p>

          <div style={{ overflowX: 'auto', overflowY: 'auto', flex: 1, minHeight: 0 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                  <th style={{ padding: '12px' }}>Time</th>
                  <th style={{ padding: '12px' }}>Rule</th>
                  <th style={{ padding: '12px' }}>Source</th>
                  <th style={{ padding: '12px' }}>Target</th>
                  <th style={{ padding: '12px' }}>Severity</th>
                  <th style={{ padding: '12px' }}>Current Attack</th>
                  <th style={{ padding: '12px' }}>Current Malware</th>
                  <th style={{ padding: '12px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {liveAlerts.map((alert, index) => {
                  const severity = getSeverity(alert);
                  const action = getActionText(alert.decision);
                  return (
                    <tr key={index} style={{ borderBottom: '1px solid #334155' }}>
                      <td style={{ padding: '14px 12px', whiteSpace: 'nowrap' }}>{alert.ts}</td>
                      <td style={{ padding: '14px 12px', fontWeight: '600' }}>
                        <div>{getEventTitle(alert)}</div>
                        {alert.family_label && (
                          <div style={{ color: '#64748b', fontSize: '11px', marginTop: '4px' }}>{alert.family_label}</div>
                        )}
                        {String(alert.rule || '').toUpperCase() === 'OBS_UNKNOWN' && (
                          <div style={{ marginTop: '6px', display: 'inline-block', border: '1px solid #0891b2', color: '#67e8f9', borderRadius: '999px', padding: '3px 8px', fontSize: '11px', fontWeight: '600' }}>
                            New / Unmatched Pattern
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '14px 12px' }}>
                        <div>{alert.src}</div>
                        <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>{alert.src_mac || 'Unknown'}</div>
                      </td>
                      <td style={{ padding: '14px 12px' }}>
                        <div>{alert.dst}</div>
                        <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>{alert.dst_mac || 'Unknown'}</div>
                      </td>
                      <td style={{ padding: '14px 12px' }}>
                        <span style={{ background: 'rgba(255,255,255,0.06)', border: `1px solid ${getSeverityColor(severity)}`, color: getSeverityColor(severity), borderRadius: '999px', padding: '4px 10px', fontSize: '12px', fontWeight: '600' }}>
                          {severity}
                        </span>
                      </td>
                      <td style={{ padding: '14px 12px', color: '#67e8f9', fontWeight: '600' }}>{scoreText(alert.atk)}</td>
                      <td style={{ padding: '14px 12px', color: '#c084fc', fontWeight: '600' }}>{scoreText(alert.mal)}</td>
                      <td style={{ padding: '14px 12px', color: getActionColor(action), fontWeight: '600' }}>{action}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div style={monitorPanelStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: '10px', marginBottom: '12px' }}>
            <div>
              <h2 style={{ marginTop: 0, marginBottom: '6px', fontSize: '18px' }}>Manual Response</h2>
              <p style={{ color: '#94a3b8', marginTop: 0, marginBottom: 0, fontSize: '13px', lineHeight: '1.5' }}>
                Review active blocks and open the exact logs you need.
              </p>
            </div>
            <div style={{ border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', borderRadius: '999px', padding: '4px 10px', fontSize: '12px', fontWeight: '700', whiteSpace: 'nowrap' }}>
              {manualResponseOpenCount} Active
            </div>
          </div>

          {manualResponseItems.length === 0 ? (
            <div style={{ background: '#0f172a', border: '1px dashed #334155', borderRadius: '14px', padding: '18px 16px', color: '#94a3b8', fontSize: '13px', lineHeight: '1.6' }}>
              {manualResponseOpenCount > 0 ? 'Open manual response items are being refreshed.' : 'No open manual response items right now.'}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', overflowY: 'auto', flex: 1, minHeight: 0, paddingRight: '4px' }}>
              {manualResponseItems.map((host, index) => {
                const statusTone = getManualResponseStatusTone(host.status);
                return (
                <div key={index} style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '13px', padding: '10px 11px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: '10px' }}>
                    <div>
                      <div style={{ fontWeight: '700', fontSize: '13px' }}>{host.ip}</div>
                      <div style={{ color: '#94a3b8', fontSize: '11px', marginTop: '4px', lineHeight: '1.35' }}>{host.reason}</div>
                    </div>
                    <div style={{ border: `1px solid ${statusTone.border}`, color: statusTone.text, background: statusTone.background, borderRadius: '999px', padding: '3px 7px', fontSize: '10px', fontWeight: '700', whiteSpace: 'nowrap' }}>
                      {host.status}
                    </div>
                  </div>

                  <div style={{ color: '#64748b', fontSize: '10px', marginTop: '7px' }}>Block Duration: {host.timeout}</div>

                  <div style={{ display: 'flex', gap: '7px', marginTop: '9px', flexWrap: 'wrap' }}>
                    <button
                      onClick={() => onUnblock(host.ip)}
                      style={{
                        background: 'rgba(34, 211, 238, 0.12)',
                        color: '#67e8f9',
                        border: '1px solid #0891b2',
                        borderRadius: '10px',
                        padding: '6px 10px',
                        cursor: 'pointer',
                        fontSize: '11px',
                      }}
                    >
                      Unblock
                    </button>
                    <button onClick={() => onViewLogs(host.ip)} style={compactButtonStyle}>
                      View Logs
                    </button>
                  </div>
                </div>
              )})}
            </div>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '18px', marginBottom: '24px', alignItems: 'stretch' }}>
        <div style={{ ...sectionStyle, display: 'flex', flexDirection: 'column', minHeight: '440px', maxHeight: '440px', padding: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: '14px', marginBottom: '14px', flexWrap: 'wrap' }}>
            <div>
              <h2 style={{ marginTop: 0, marginBottom: '8px' }}>Threat Overview</h2>
              <p style={{ color: '#94a3b8', marginTop: 0, marginBottom: 0 }}>
                Attack and malware families ordered by cumulative detection count.
              </p>
            </div>
            <div style={{ border: '1px solid rgba(34, 211, 238, 0.35)', color: '#67e8f9', borderRadius: '999px', padding: '5px 12px', fontSize: '12px', fontWeight: '700' }}>
              {cumulativeThreatOverviewTotal} detections
            </div>
          </div>

          <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '16px', padding: '14px 16px', flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            <div style={{ color: '#94a3b8', fontSize: '12px', marginBottom: '10px' }}>Cumulative Threat Frequency</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', overflowY: 'auto', flex: 1, minHeight: 0, paddingRight: '4px' }}>
              {cumulativeThreatOverviewItems.map((item, index) => (
                <div
                  key={item.key}
                  style={{
                    position: 'relative',
                    display: 'grid',
                    gridTemplateColumns: 'minmax(0, 1fr) auto',
                    alignItems: 'center',
                    gap: '16px',
                    background: index === 0 ? 'linear-gradient(135deg, rgba(34, 211, 238, 0.08), rgba(99, 102, 241, 0.10))' : 'rgba(255,255,255,0.02)',
                    border: `1px solid ${index === 0 ? 'rgba(34, 211, 238, 0.22)' : '#334155'}`,
                    borderRadius: '14px',
                    padding: '13px 14px 13px 16px',
                  }}
                >
                  <div
                    style={{
                      position: 'absolute',
                      left: '0',
                      top: '12px',
                      bottom: '12px',
                      width: '3px',
                      borderRadius: '999px',
                      background: index === 0 ? 'linear-gradient(180deg, #22d3ee, #6366f1)' : 'rgba(100, 116, 139, 0.45)',
                    }}
                  />

                  <div style={{ minWidth: 0, paddingLeft: '2px' }}>
                    <div style={{ fontWeight: '700', fontSize: '15px', lineHeight: '1.35', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {item.title}
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '5px' }}>
                      {item.count} detections
                    </div>
                  </div>

                  <div style={{ textAlign: 'right', minWidth: '70px' }}>
                    <div style={{ color: '#f8fafc', fontSize: '22px', fontWeight: '800', lineHeight: '1' }}>
                      {item.count}
                    </div>
                    <div style={{ color: '#64748b', fontSize: '10px', marginTop: '5px', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                      Count
                    </div>
                  </div>
                </div>
              ))}
              {cumulativeThreatOverviewItems.length === 0 && (
                <div style={{ color: '#94a3b8', fontSize: '13px' }}>No frequent threat families yet.</div>
              )}
            </div>
          </div>
        </div>

        <div style={{ ...sectionStyle, display: 'flex', flexDirection: 'column', minHeight: '440px', maxHeight: '440px', padding: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: '14px', marginBottom: '14px', flexWrap: 'wrap' }}>
            <div>
              <h2 style={{ marginTop: 0, marginBottom: '8px' }}>Honeypot</h2>
              <p style={{ color: '#94a3b8', marginTop: 0, marginBottom: 0 }}>
                Redirected SSH sources and the latest decoy activity.
              </p>
            </div>
            <div style={{ border: '1px solid rgba(168, 85, 247, 0.35)', color: '#c4b5fd', borderRadius: '999px', padding: '5px 12px', fontSize: '12px', fontWeight: '700' }}>
              {honeypotPanel.recent.length} redirects
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1, minHeight: 0 }}>
            <div style={{ background: 'rgba(168, 85, 247, 0.10)', border: '1px solid rgba(168, 85, 247, 0.35)', borderRadius: '16px', padding: '14px 16px' }}>
              <div style={{ color: '#c4b5fd', fontSize: '12px', marginBottom: '8px' }}>Latest Redirected Source</div>
              <div style={{ fontSize: '18px', fontWeight: '700', lineHeight: '1.45' }}>
                {honeypotPanel.latest ? `${honeypotPanel.latest.src} -> Honeypot VM` : 'No active honeypot redirect'}
              </div>
              <div style={{ color: '#cbd5e1', fontSize: '13px', lineHeight: '1.6', marginTop: '10px' }}>
                {honeypotPanel.latest ? `Reason: ${getEventTitle(honeypotPanel.latest)}` : 'Suspicious SSH sources redirected to the decoy will appear here.'}
              </div>
            </div>

            <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '16px', padding: '14px 16px', flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
              <div style={{ color: '#94a3b8', fontSize: '12px', marginBottom: '10px' }}>Recent Honeypot Activity</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', overflowY: 'auto', flex: 1, minHeight: 0, paddingRight: '4px' }}>
                {honeypotPanel.recent.map((item, index) => (
                  <div key={`${item.ts}-${index}`} style={{ display: 'grid', gridTemplateColumns: '10px 1fr', gap: '10px', alignItems: 'start' }}>
                    <div style={{ width: '10px', height: '10px', marginTop: '5px', borderRadius: '999px', background: '#a855f7' }} />
                    <div>
                      <div style={{ fontWeight: '700', fontSize: '13px', marginBottom: '4px' }}>{item.ts}</div>
                      <div style={{ color: '#cbd5e1', fontSize: '13px', lineHeight: '1.5' }}>
                        {item.src} redirected after {getEventTitle(item)}
                      </div>
                    </div>
                  </div>
                ))}
                {honeypotPanel.recent.length === 0 && (
                  <div style={{ color: '#94a3b8', fontSize: '13px' }}>No honeypot redirects yet.</div>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <button
                onClick={() => honeypotLogTargetIp && onViewHoneypotLogs(honeypotLogTargetIp)}
                disabled={!honeypotLogTargetIp}
                style={{
                  ...compactButtonStyle,
                  background: 'rgba(168, 85, 247, 0.12)',
                  border: '1px solid rgba(168, 85, 247, 0.35)',
                  color: honeypotLogTargetIp ? '#c4b5fd' : '#64748b',
                  cursor: honeypotLogTargetIp ? 'pointer' : 'not-allowed',
                }}
              >
                Open Honeypot Logs
              </button>
            </div>
          </div>
        </div>
      </div>

      <div style={{ marginBottom: '24px' }}>
        <div style={sectionStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: '16px', marginBottom: '18px', flexWrap: 'wrap' }}>
            <div>
              <h2 style={{ marginTop: 0, marginBottom: '8px' }}>Router Status</h2>
              <p style={{ color: '#94a3b8', marginTop: 0, marginBottom: 0 }}>Real-time router resources, NetFlow ingestion, and firewall enforcement status.</p>
            </div>
            <div style={{ border: '1px solid rgba(16, 185, 129, 0.35)', color: '#86efac', borderRadius: '999px', padding: '5px 12px', fontSize: '12px', fontWeight: '700' }}>
              {routerStatus.reachable ? 'Core services online' : 'Partial / degraded'}
            </div>
          </div>

          <div style={{ background: 'rgba(168, 85, 247, 0.08)', border: '1px solid rgba(168, 85, 247, 0.35)', borderRadius: '16px', padding: '12px 14px', marginBottom: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', gap: '12px', flexWrap: 'wrap' }}>
              <div>
                <div style={{ color: '#c4b5fd', fontSize: '12px', marginBottom: '8px' }}>Router Connectivity</div>
                <div style={{ fontSize: '16px', fontWeight: '700' }}>{routerStatus.identity || routerStatus.routerIp || '-'}</div>
              </div>
              <div style={{ border: `1px solid ${routerStatus.reachable ? '#22c55e' : '#f59e0b'}`, color: routerStatus.reachable ? '#86efac' : '#fcd34d', borderRadius: '999px', padding: '4px 10px', fontSize: '11px', fontWeight: '700' }}>
                {routerStatus.status || 'Unknown'}
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '10px', marginTop: '12px' }}>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '11px' }}>Version</div>
                <div style={{ color: '#e2e8f0', fontSize: '14px', fontWeight: '600', marginTop: '4px' }}>{routerStatus.version || '-'}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '11px' }}>Uptime</div>
                <div style={{ color: '#e2e8f0', fontSize: '14px', fontWeight: '600', marginTop: '4px' }}>{uptimeDisplay}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '11px' }}>Router IP</div>
                <div style={{ color: '#e2e8f0', fontSize: '14px', fontWeight: '600', marginTop: '4px' }}>{routerStatus.routerIp || '-'}</div>
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '10px' }}>
            <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
              <div style={{ color: '#94a3b8', fontSize: '13px' }}>CPU Load</div>
              <div style={{ fontSize: '28px', fontWeight: '700', marginTop: '8px' }}>{formatPercent(routerStatus.cpuLoad)}</div>
              <div style={{ color: '#64748b', fontSize: '12px', marginTop: '8px' }}>Router snapshot {routerControlAge}</div>
            </div>
            <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
              <div style={{ color: '#94a3b8', fontSize: '13px' }}>Memory Usage</div>
              <div style={{ fontSize: '28px', fontWeight: '700', marginTop: '8px' }}>{formatPercent(routerStatus.memoryUsagePercent)}</div>
              <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '8px' }}>
                {routerStatus.usedMemoryMb ?? '-'} MB used / {routerStatus.totalMemoryMb ?? '-'} MB total
              </div>
            </div>
            <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
              <div style={{ color: '#94a3b8', fontSize: '13px' }}>Flow Ingestion</div>
              <div style={{ fontSize: '28px', fontWeight: '700', marginTop: '8px' }}>{formatCount(flowRecordsRate)}/s</div>
              <div style={{ color: '#64748b', fontSize: '12px', marginTop: '8px' }}>
                {formatCount(flowRecordsTotal)} total flows | {activeAggregates} active aggregates | {flowMetricsAge}
              </div>
            </div>
            <div style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '14px', padding: '14px' }}>
              <div style={{ color: '#94a3b8', fontSize: '13px' }}>Firewall Enforcement</div>
              <div style={{ fontSize: '28px', fontWeight: '700', marginTop: '8px' }}>
                {formatCount(firewallEnforcementCount)}
              </div>
              <div style={{ color: '#64748b', fontSize: '12px', marginTop: '8px' }}>
                {formatCount(routerStatus.blockedCount ?? 0)} blocked | {formatCount(routerStatus.honeypotCount ?? 0)} honeypot | {routerControlAge}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
