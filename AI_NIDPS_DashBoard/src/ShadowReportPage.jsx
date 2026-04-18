import { useMemo, useState } from "react";

export default function ShadowReportPage({ shadowReport, helpers, onOpenOnlineLearning }) {
  const { scoreText } = helpers;
  const [activeType, setActiveType] = useState("all");
  const [activeStage, setActiveStage] = useState("all");
  const [sortMode, setSortMode] = useState("difference");
  const [query, setQuery] = useState("");

  const currentPeakScore = (item) => {
    const primary = Number(item?.currentMax);
    if (Number.isFinite(primary)) return primary;
    const fallback = Number(item?.currentAvg);
    return Number.isFinite(fallback) ? fallback : 0;
  };

  const shadowPeakScore = (item) => {
    const primary = Number(item?.shadowMax);
    if (Number.isFinite(primary)) return primary;
    const fallback = Number(item?.shadowAvg);
    return Number.isFinite(fallback) ? fallback : 0;
  };

  const sectionStyle = {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: "16px",
    padding: "20px",
  };

  const allItems = useMemo(() => {
    const attackItems = (shadowReport.attack || []).map((item) => ({ ...item, bucket: "attack" }));
    const malwareItems = (shadowReport.malware || []).map((item) => ({ ...item, bucket: "malware" }));
    return [...attackItems, ...malwareItems];
  }, [shadowReport]);

  const visibleItems = useMemo(() => {
    const normalizedQuery = String(query || "").trim().toLowerCase();
    let items = allItems.filter((item) => {
      if (activeType !== "all" && item.bucket !== activeType) return false;
      if (activeStage === "trained" && !item.trainedSeen) return false;
      if (activeStage === "ready" && !item.readySeen) return false;
      if (!normalizedQuery) return true;
      const haystack = `${item.title} ${item.family} ${item.latestTs}`.toLowerCase();
      return haystack.includes(normalizedQuery);
    });

    items = [...items].sort((a, b) => {
      const aCurrentPeak = currentPeakScore(a);
      const bCurrentPeak = currentPeakScore(b);
      const aShadowPeak = shadowPeakScore(a);
      const bShadowPeak = shadowPeakScore(b);
      const aPeakDelta = aShadowPeak - aCurrentPeak;
      const bPeakDelta = bShadowPeak - bCurrentPeak;

      if (sortMode === "latest") return String(b.latestTs || "").localeCompare(String(a.latestTs || ""));
      if (sortMode === "shadow") return bShadowPeak - aShadowPeak;
      if (sortMode === "current") return bCurrentPeak - aCurrentPeak;
      return Math.abs(bPeakDelta) - Math.abs(aPeakDelta);
    });

    return items;
  }, [activeStage, activeType, allItems, query, sortMode]);

  const reportSummary = useMemo(() => {
    const biggestDifference =
      visibleItems.reduce((largest, item) => {
        if (!largest) return item;
        const itemDelta = Math.abs(shadowPeakScore(item) - currentPeakScore(item));
        const largestDelta = Math.abs(shadowPeakScore(largest) - currentPeakScore(largest));
        return itemDelta > largestDelta ? item : largest;
      }, null) || null;
    const mostRecent = [...visibleItems].sort((a, b) => String(b.latestTs || "").localeCompare(String(a.latestTs || "")))[0] || null;
    return { biggestDifference, mostRecent };
  }, [visibleItems]);

  const tabStyle = (active) => ({
    background: active ? "rgba(34, 211, 238, 0.14)" : "rgba(255,255,255,0.03)",
    color: active ? "#67e8f9" : "#cbd5e1",
    border: `1px solid ${active ? "#0891b2" : "#334155"}`,
    borderRadius: "999px",
    padding: "8px 14px",
    cursor: "pointer",
    fontWeight: "600",
  });

  const deltaTone = (delta) => {
    if (delta >= 0.2) return { color: "#f9a8d4", label: "Shadow Higher" };
    if (delta <= -0.2) return { color: "#cbd5e1", label: "Current Higher" };
    return { color: "#93c5fd", label: "Close Match" };
  };

  const bucketTone = (bucket) =>
    bucket === "malware"
      ? { border: "#ef4444", text: "#fca5a5", label: "Malware" }
      : { border: "#f97316", text: "#fdba74", label: "Attack" };

  return (
    <div style={sectionStyle}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", gap: "14px", marginBottom: "18px", flexWrap: "wrap" }}>
        <div>
          <h2 style={{ marginTop: 0, marginBottom: "8px" }}>Online Learning Comparison</h2>
          <p style={{ color: "#94a3b8", marginTop: 0, marginBottom: 0, maxWidth: "920px" }}>
            This page only uses samples that already entered the online learning pipeline. It compares your current production model with the shadow model by family, so you can see what the online learner is doing without mixing in raw live alerts.
          </p>
        </div>

        <button
          onClick={onOpenOnlineLearning}
          style={{
            background: "rgba(34, 211, 238, 0.12)",
            color: "#67e8f9",
            border: "1px solid #0891b2",
            borderRadius: "10px",
            padding: "10px 14px",
            cursor: "pointer",
          }}
        >
          Back To Online Learning
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr 1fr 1fr", gap: "14px", marginBottom: "18px" }}>
        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
          <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Search Online Learning Families</div>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search by display name, family label, or time"
            style={{
              width: "100%",
              background: "rgba(255,255,255,0.03)",
              color: "#e2e8f0",
              border: "1px solid #334155",
              borderRadius: "10px",
              padding: "10px 12px",
              outline: "none",
              boxSizing: "border-box",
            }}
          />
        </div>

        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
          <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Filter Type</div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <button onClick={() => setActiveType("all")} style={tabStyle(activeType === "all")}>All</button>
            <button onClick={() => setActiveType("attack")} style={tabStyle(activeType === "attack")}>Attack</button>
            <button onClick={() => setActiveType("malware")} style={tabStyle(activeType === "malware")}>Malware</button>
          </div>
        </div>

        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
          <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Online Sample Stage</div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <button onClick={() => setActiveStage("all")} style={tabStyle(activeStage === "all")}>All</button>
            <button onClick={() => setActiveStage("ready")} style={tabStyle(activeStage === "ready")}>Ready</button>
            <button onClick={() => setActiveStage("trained")} style={tabStyle(activeStage === "trained")}>Trained</button>
          </div>
        </div>

        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
          <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Sort By</div>
          <select
            value={sortMode}
            onChange={(event) => setSortMode(event.target.value)}
            style={{
              width: "100%",
              background: "rgba(255,255,255,0.03)",
              color: "#e2e8f0",
              border: "1px solid #334155",
              borderRadius: "10px",
              padding: "10px 12px",
              outline: "none",
            }}
          >
            <option value="difference">Largest Difference</option>
            <option value="shadow">Highest Shadow</option>
            <option value="current">Highest Current</option>
            <option value="latest">Most Recent</option>
          </select>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px", marginBottom: "18px" }}>
        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
          <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Biggest Model Difference</div>
          {reportSummary.biggestDifference ? (
            <>
              <div style={{ fontSize: "18px", fontWeight: "700" }}>{reportSummary.biggestDifference.title}</div>
              <div style={{ color: "#64748b", fontSize: "12px", marginTop: "4px" }}>{reportSummary.biggestDifference.family}</div>
              <div style={{ color: "#e2e8f0", marginTop: "10px", fontSize: "13px" }}>
                Production {scoreText(currentPeakScore(reportSummary.biggestDifference))} vs Online {scoreText(shadowPeakScore(reportSummary.biggestDifference))} | Peak Difference {scoreText(Math.abs(shadowPeakScore(reportSummary.biggestDifference) - currentPeakScore(reportSummary.biggestDifference)))}
              </div>
            </>
          ) : (
            <div style={{ color: "#94a3b8", fontSize: "13px" }}>No items matched this filter.</div>
          )}
        </div>

        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
          <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Report Scope</div>
          <div style={{ fontSize: "18px", fontWeight: "700" }}>
            Total {(shadowReport.source?.ready ?? 0) + (shadowReport.source?.trained ?? 0)} | Ready {shadowReport.source?.ready ?? 0} | Trained {shadowReport.source?.trained ?? 0}
          </div>
          <div style={{ color: "#94a3b8", marginTop: "8px", fontSize: "13px" }}>
            This report uses ready and trained online-learning samples only. Raw live alert events are excluded.
          </div>
        </div>

        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
          <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Latest Online Learning Family</div>
          {reportSummary.mostRecent ? (
            <>
              <div style={{ fontSize: "18px", fontWeight: "700" }}>{reportSummary.mostRecent.title}</div>
              <div style={{ color: "#64748b", fontSize: "12px", marginTop: "4px" }}>{reportSummary.mostRecent.family}</div>
              <div style={{ color: "#e2e8f0", marginTop: "10px", fontSize: "13px" }}>
                Last seen {reportSummary.mostRecent.latestTs || "-"}
              </div>
            </>
          ) : (
            <div style={{ color: "#94a3b8", fontSize: "13px" }}>No items matched this filter.</div>
          )}
        </div>
      </div>

      {visibleItems.length === 0 ? (
        <div style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "18px", color: "#94a3b8" }}>
          No shadow report items matched the current filter.
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "14px" }}>
          {visibleItems.map((item) => {
            const currentPeak = currentPeakScore(item);
            const shadowPeak = shadowPeakScore(item);
            const peakDelta = shadowPeak - currentPeak;
            const delta = deltaTone(peakDelta);
            const bucket = bucketTone(item.bucket);
            return (
              <div key={item.key} style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "16px", padding: "16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", gap: "10px" }}>
                  <div>
                    <div style={{ fontWeight: "700", fontSize: "18px" }}>{item.title}</div>
                    <div style={{ color: "#64748b", fontSize: "12px", marginTop: "4px" }}>{item.family}</div>
                  </div>

                  <div
                    style={{
                      border: `1px solid ${bucket.border}`,
                      color: bucket.text,
                      borderRadius: "999px",
                      padding: "4px 10px",
                      fontSize: "11px",
                      fontWeight: "700",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {bucket.label}
                  </div>
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginTop: "16px" }}>
                  <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #334155", borderRadius: "12px", padding: "12px" }}>
                    <div style={{ color: "#94a3b8", fontSize: "11px" }}>Current Model (Highest)</div>
                    <div style={{ color: "#67e8f9", fontSize: "24px", fontWeight: "700", marginTop: "6px" }}>{scoreText(currentPeak)}</div>
              </div>

              <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #334155", borderRadius: "12px", padding: "12px" }}>
                    <div style={{ color: "#94a3b8", fontSize: "11px" }}>Online Learning Shadow (Highest Comparable)</div>
                    <div style={{ color: "#86efac", fontSize: "24px", fontWeight: "700", marginTop: "6px" }}>{scoreText(shadowPeak)}</div>
                  </div>
                </div>

                <div
                  style={{
                    marginTop: "12px",
                    background: "rgba(255,255,255,0.03)",
                    border: "1px solid #334155",
                    borderRadius: "12px",
                    padding: "12px",
                    color: "#cbd5e1",
                    fontSize: "12px",
                  }}
                >
                  <strong>Online Samples:</strong> Total {item.sampleCount ?? 0} | Ready {item.readyCount ?? 0} | Trained {item.trainedCount ?? 0}
                </div>

                <div
                  style={{
                    marginTop: "12px",
                    background: "rgba(255,255,255,0.03)",
                    border: "1px solid #334155",
                    borderRadius: "12px",
                    padding: "12px",
                    color: "#cbd5e1",
                    fontSize: "12px",
                  }}
                >
                  <strong>Training Attempts:</strong> {item.trainAttemptCount ?? 0} | Eval Rejects {item.rejectCount ?? 0}
                  <div style={{ color: "#94a3b8", marginTop: "6px" }}>
                    Last train try {item.latestTrainAttemptAt || "-"} | Last reject {item.latestRejectedAt || "-"}
                  </div>
                </div>

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "14px", gap: "12px", flexWrap: "wrap" }}>
                  <div
                    style={{
                      border: `1px solid ${delta.color}`,
                      color: delta.color,
                      borderRadius: "999px",
                      padding: "5px 10px",
                      fontSize: "12px",
                      fontWeight: "700",
                    }}
                  >
                    {delta.label} | Peak Difference {scoreText(Math.abs(peakDelta))}
                  </div>

                  <div style={{ color: "#94a3b8", fontSize: "12px" }}>
                    {item.trainedSeen && item.readySeen ? "Online Stage: Ready + Trained" : item.trainedSeen ? "Online Stage: Trained" : "Online Stage: Ready"} | Last seen {item.latestTs || "-"}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
