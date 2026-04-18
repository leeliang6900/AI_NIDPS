export default function OnlineLearningPage({
  modelOverview,
  learningStats,
  pendingSamples,
  candidateSamples,
  readySamples,
  actionMessage,
  onShadowCaptureToggle,
  onAutoTrainToggle,
  onManualLabel,
  onRollbackShadow,
  onLiveDecisionSourceChange,
  onOpenReport,
  helpers,
}) {
  const { scoreText, getEvalStatusColor, getReadableRule, familyText } = helpers;

  const sectionStyle = {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: "16px",
    padding: "20px",
  };

  const modeTitle = (mode) =>
    ({
      pending: "Pending Labels",
      candidate: "Review Candidates",
      ready: "Ready To Train",
    }[mode] || "Samples");

  const modeHint = (mode) =>
    ({
      pending: "These samples are captured, but they still need trusted labels before they can enter online learning.",
      candidate: "These samples were auto-labeled from heuristic or unknown traffic patterns and still need a trusted human review.",
      ready: "These samples are labeled and visible to online learning. First family seeds go first, new variants and recalibration targets are picked next, and repeated rejects stay visible but wait for a new variant.",
    }[mode] || "");

  const learningReasonText = (reason) =>
    ({
      manual_label: "Manual label",
      novel_pattern: "New pattern",
      novel_variant_followup: "New variant follow-up",
      stable_family_seed: "First sample for this family",
      stable_family_recalibration: "Needs recalibration",
      stable_family_followup: "Known family follow-up",
      stable_known_family: "Known family sample",
      candidate_pattern: "Candidate pattern",
      candidate_followup: "Candidate follow-up",
      retry_after_failed_train: "Retry after earlier rejected training",
      retry_limit_reached: "Waiting for a new variant after repeated rejected training",
    }[String(reason || "")] || "Ready to learn");

  const friendlyEvalReason = (status, reason) => {
    const raw = String(reason || "").trim();
    if (!raw) return "-";
    const notes = [];
    if (raw.includes("reference guard set too small")) notes.push("There are still too few earlier samples to judge this update safely.");
    if (raw.includes("batch attack confidence did not improve")) notes.push("This try did not make the attack side more confident.");
    if (raw.includes("batch attack negatives became too hot")) notes.push("This try made normal attack-side traffic look too suspicious.");
    if (raw.includes("batch malware confidence did not improve")) notes.push("This try did not make the malware side more confident.");
    if (raw.includes("batch malware negatives became too hot")) notes.push("This try made normal malware-side traffic look too suspicious.");
    if (raw.includes("attack benign false-positive rate increased too much")) notes.push("This try raised attack false alarms too much.");
    if (raw.includes("malware benign false-positive rate increased too much")) notes.push("This try raised malware false alarms too much.");
    if (!notes.length) return raw;
    if (String(status || "").toLowerCase().includes("reject")) {
      return `This update was not saved. ${notes.join(" ")}`;
    }
    return notes.join(" " );
  };

  const learningBaseScore = (reason) =>
    ({
      manual_label: 10.0,
      novel_pattern: 7.0,
      stable_family_seed: 7.0,
      stable_family_recalibration: 6.5,
      candidate_pattern: 5.0,
    }[String(reason || "")] || 0.0);

  const learningBreakdown = (sample) => {
    const features = sample?.features || {};
    const flows = Number(features.flows || 0);
    const uniqDports = Number(features.uniq_dports || 0);
    const pktsRate = Number(features.pkts_rate || 0);
    const bytesRate = Number(features.bytes_rate || 0);
    const novelty = Number(sample?.novelty_score || 0);

    const base = learningBaseScore(sample?.learn_reason);
    const flowBonus = (flows >= 20 ? 0.8 : 0) + (flows >= 100 ? 0.8 : 0);
    const dportBonus = (uniqDports >= 5 ? 0.6 : 0) + (uniqDports >= 20 ? 0.6 : 0);
    const packetBonus = (pktsRate >= 20 ? 0.5 : 0) + (pktsRate >= 100 ? 0.7 : 0);
    const byteBonus = (bytesRate >= 1000 ? 0.5 : 0) + (bytesRate >= 10000 ? 0.8 : 0);
    const noveltyBonus = (novelty >= 0.35 ? 0.8 : 0) + (novelty >= 0.6 ? 1.0 : 0) + (novelty >= 0.8 ? 1.0 : 0);
    const total = Number(sample?.learn_weight || 0);

    return { base, flowBonus, dportBonus, packetBonus, byteBonus, noveltyBonus, total };
  };

  const learningBreakdownText = (sample) => {
    const breakdown = learningBreakdown(sample);
    if (!breakdown.total) return "Learning score is 0.00 for this sample.";
    const hasFeatures = sample?.features && Object.keys(sample.features).length > 0;
    if (!hasFeatures) {
      const signalBonus = Math.max(0, breakdown.total - breakdown.base);
      return `Learning score ${scoreText(breakdown.total)} = Priority ${scoreText(breakdown.base)} + Signal bonus ${scoreText(signalBonus)}`;
    }
    return `Learning score ${scoreText(breakdown.total)} = Priority ${scoreText(breakdown.base)} + Flow ${scoreText(breakdown.flowBonus)} + Port ${scoreText(breakdown.dportBonus)} + Packet ${scoreText(breakdown.packetBonus)} + Byte ${scoreText(breakdown.byteBonus)} + Novelty ${scoreText(breakdown.noveltyBonus)}`;
  };

  const sampleStatusText = (sample, mode) => {
    if (sample?.trained) return "Already Learned";
    if (mode === "pending" || sample?.label_status === "pending") return "Waiting For Label";
    if (mode === "candidate" || sample?.label_status === "candidate") return "Waiting For Review";
    if (!sample?.learn_eligible && Number(sample?.train_attempt_count || 0) > 0) return "Waiting For New Variant";
    if (Number(sample?.train_attempt_count || 0) > 0) return "Training Tried, Waiting For Acceptance";
    return "Ready To Learn";
  };

  const countText = (value) => {
    const num = Number(value);
    if (!Number.isFinite(num)) return "-";
    return `${Math.round(num)}`;
  };

  const bytesText = (value) => {
    const num = Number(value);
    if (!Number.isFinite(num)) return "-";
    if (num >= 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(2)} MB`;
    if (num >= 1024) return `${(num / 1024).toFixed(1)} KB`;
    return `${Math.round(num)} B`;
  };

  const percentText = (value) => {
    const num = Number(value);
    if (!Number.isFinite(num)) return "-";
    return `${(num * 100).toFixed(0)}%`;
  };

  const evidenceText = (sample) => {
    const features = sample?.features || {};
    const proto = sample?.proto_label || "-";
    const topDport = sample?.top_dport ?? "-";
    const flows = sample?.flows ?? features?.flows;
    const uniqDports = sample?.uniq_dports ?? features?.uniq_dports;
    return `Traffic: ${proto} | Top port ${topDport} | Flows ${countText(flows)} | Unique dst ports ${countText(uniqDports)}`;
  };

  const volumeText = (sample) => {
    const features = sample?.features || {};
    const totalPkts =
      sample?.total_pkts ??
      ((Number.isFinite(Number(sample?.spkts)) || Number.isFinite(Number(sample?.dpkts)))
        ? Number(sample?.spkts || 0) + Number(sample?.dpkts || 0)
        : Number(features?.Spkts || 0) + Number(features?.Dpkts || 0));
    const totalBytes =
      sample?.total_bytes ??
      ((Number.isFinite(Number(sample?.sbytes)) || Number.isFinite(Number(sample?.dbytes)))
        ? Number(sample?.sbytes || 0) + Number(sample?.dbytes || 0)
        : Number(features?.sbytes || 0) + Number(features?.dbytes || 0));
    const topPortRatio = features?.top_port_ratio;
    return `Volume: Packets ${countText(totalPkts)} | Bytes ${bytesText(totalBytes)} | Top-port ratio ${percentText(topPortRatio)}`;
  };

  const evidenceContextText = (sample) => {
    const familySource = sample?.family_source || "-";
    const confidence = sample?.family_confidence || "-";
    const novelty = scoreText(sample?.novelty_score);
    return `Decision: ${sample?.decision || "-"} | Family source: ${familySource} | Confidence: ${confidence} | Novelty: ${novelty}`;
  };

  const readyTitleText = (sample) => {
    if (sample?.display_label) return sample.display_label;
    if (sample?.family_label) return sample.family_label;
    if (sample?.rule) return getReadableRule(sample.rule);
    return "Unknown Traffic";
  };

  const reviewReasonText = (sample) => {
    const reasons = [];
    const confidence = String(sample?.family_confidence || "").toLowerCase();
    const familySource = String(sample?.family_source || "").toLowerCase();
    const labelSource = String(sample?.label_source || "").toLowerCase();
    const familyLabel = String(sample?.family_label || "").toLowerCase();
    const novelty = Number(sample?.novelty_score || 0);
    const attackScore = Number(sample?.current_attack_score ?? sample?.xgb_attack_score ?? 0);
    const malwareScore = Number(sample?.current_malware_score ?? sample?.xgb_malware_score ?? 0);

    if (confidence) reasons.push(`confidence is ${confidence}`);
    if (labelSource.startsWith("auto_family_default_") || labelSource.startsWith("auto_family_unknown_")) {
      reasons.push("it was auto-labeled from a default or unknown family");
    } else if (familySource === "behavior_heuristic") {
      reasons.push("it came from heuristic family matching");
    }
    if (novelty >= 0.65) reasons.push(`novelty is ${scoreText(novelty)}`);
    if (familyLabel.includes("unknown") || familyLabel.includes("unclassified") || familyLabel.endsWith("_like")) {
      reasons.push("the family label is still uncertain");
    }
    if (Math.max(attackScore, malwareScore) >= 0.6) {
      reasons.push("its risk score is not low");
    }

    return reasons.length ? reasons.slice(0, 3).join(" | ") : "This auto-labeled sample still needs a manual review.";
  };

  const renderSampleList = (items, emptyText, mode) => (
    <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
      <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "4px" }}>{modeTitle(mode)}</div>
      <div style={{ color: "#64748b", fontSize: "12px", marginBottom: "10px" }}>{modeHint(mode)}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: "10px", maxHeight: "340px", overflowY: "auto" }}>
        {items.length === 0 ? (
          <div style={{ color: "#94a3b8", fontSize: "13px" }}>{emptyText}</div>
        ) : (
          items.map((sample) => (
            <div key={sample.event_id} style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "12px", padding: "12px" }}>
              <div style={{ fontWeight: "700", fontSize: "13px" }}>
                {mode === "ready" ? readyTitleText(sample) : (sample?.display_label || getReadableRule(sample.rule))}
              </div>
              <div style={{ color: "#94a3b8", fontSize: "12px", marginTop: "4px" }}>{`${sample.src} -> ${sample.dst}`}</div>
              <div style={{ color: "#64748b", fontSize: "11px", marginTop: "4px" }}>{sample.ts}</div>
              {mode === "candidate" && (
                <div style={{ color: "#fdba74", fontSize: "12px", marginTop: "8px" }}>
                  Review reason: {reviewReasonText(sample)}
                </div>
              )}
              <div style={{ color: "#cbd5e1", fontSize: "12px", marginTop: "8px" }}>
                Status: {sampleStatusText(sample, mode)}
              </div>
              {mode !== "candidate" && (
                <div style={{ color: "#cbd5e1", fontSize: "12px", marginTop: "8px" }}>
                  {evidenceContextText(sample)}
                </div>
              )}
              <div style={{ color: "#94a3b8", fontSize: "12px", marginTop: "8px" }}>
                {evidenceText(sample)}
              </div>
              <div style={{ color: "#94a3b8", fontSize: "12px", marginTop: "6px" }}>
                {volumeText(sample)}
              </div>

              {mode === "ready" ? (
                <>
                  <div style={{ color: "#67e8f9", fontSize: "12px", marginTop: "8px" }}>{familyText(sample)}</div>
                  <div style={{ color: "#cbd5e1", fontSize: "12px", marginTop: "8px" }}>
                    Labels: attack={sample.attack_label ?? "-"} malware={sample.malware_label ?? "-"} | Source: {sample.label_source || "-"}
                  </div>
                  <div style={{ color: "#cbd5e1", fontSize: "12px", marginTop: "8px" }}>
                    Policy reason: {learningReasonText(sample.learn_reason)}
                  </div>
                  <div style={{ color: "#94a3b8", fontSize: "12px", marginTop: "8px" }}>
                    {learningBreakdownText(sample)}
                  </div>
                  {Number(sample.train_attempt_count || 0) > 0 && (
                    <div style={{ color: "#cbd5e1", fontSize: "12px", marginTop: "8px" }}>
                      Training attempts: {sample.train_attempt_count}{sample.last_train_attempt_at ? ` | Last try: ${sample.last_train_attempt_at}` : ""}
                    </div>
                  )}
                  {Number(sample.reject_count || 0) > 0 && (
                    <div style={{ color: "#fcd34d", fontSize: "12px", marginTop: "8px" }}>
                      Shadow eval rejected: {sample.reject_count} {sample.reject_count === 1 ? "time" : "times"}
                    </div>
                  )}
                </>
              ) : mode === "candidate" ? (
                <>
                  <div style={{ color: "#cbd5e1", fontSize: "12px", marginTop: "8px" }}>
                    {evidenceContextText(sample)}
                  </div>
                  <div style={{ color: "#cbd5e1", fontSize: "12px", marginTop: "8px" }}>
                    Auto labels: attack={sample.attack_label ?? "-"} malware={sample.malware_label ?? "-"} | Source: {sample.label_source || "-"}
                  </div>
                  <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "10px" }}>
                    <button
                      onClick={() => onManualLabel?.(sample, 0, 0)}
                      style={{
                        background: "rgba(34, 197, 94, 0.12)",
                        color: "#86efac",
                        border: "1px solid #15803d",
                        borderRadius: "10px",
                        padding: "8px 12px",
                        cursor: "pointer",
                        fontSize: "12px",
                        fontWeight: "600",
                      }}
                    >
                      Mark Benign
                    </button>
                    <button
                      onClick={() => onManualLabel?.(sample, 1, 0)}
                      style={{
                        background: "rgba(249, 115, 22, 0.12)",
                        color: "#fdba74",
                        border: "1px solid #ea580c",
                        borderRadius: "10px",
                        padding: "8px 12px",
                        cursor: "pointer",
                        fontSize: "12px",
                        fontWeight: "600",
                      }}
                    >
                      Mark Attack
                    </button>
                    <button
                      onClick={() => onManualLabel?.(sample, 0, 1)}
                      style={{
                        background: "rgba(239, 68, 68, 0.12)",
                        color: "#fca5a5",
                        border: "1px solid #dc2626",
                        borderRadius: "10px",
                        padding: "8px 12px",
                        cursor: "pointer",
                        fontSize: "12px",
                        fontWeight: "600",
                      }}
                    >
                      Mark Malware
                    </button>
                  </div>
                </>
              ) : (
                <div style={{ color: "#94a3b8", fontSize: "12px", marginTop: "8px" }}>
                  Waiting for auto-label or a trusted label source.
                </div>
              )}

              <div style={{ color: "#cbd5e1", fontSize: "12px", marginTop: "8px" }}>
                {mode === "candidate" ? "Representative" : "Current"} A/M: {scoreText(sample.current_attack_score ?? sample.xgb_attack_score)} / {scoreText(sample.current_malware_score ?? sample.xgb_malware_score)} | Shadow A/M (Comparable): {scoreText(sample.display_latest_online_attack_score ?? sample.display_online_attack_score ?? sample.latest_online_attack_score ?? sample.online_attack_score)} / {scoreText(sample.display_latest_online_malware_score ?? sample.display_online_malware_score ?? sample.latest_online_malware_score ?? sample.online_malware_score)}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );

  return (
    <>
      {actionMessage && (
        <div
          style={{
            marginBottom: "16px",
            background: "rgba(34, 211, 238, 0.10)",
            border: "1px solid rgba(34, 211, 238, 0.35)",
            color: "#67e8f9",
            borderRadius: "12px",
            padding: "12px 14px",
          }}
        >
          {actionMessage}
        </div>
      )}

      <div style={sectionStyle}>
        <h2 style={{ marginTop: 0, marginBottom: "8px" }}>Online Learning</h2>
        <p style={{ color: "#94a3b8", marginTop: 0, marginBottom: "20px" }}>
          Continuous online learning for adaptive threat detection and safer model evolution.
        </p>

        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "16px" }}>
          <div
            style={{
              border: `1px solid ${modelOverview.learning.shadowCaptureEnabled ? "#22c55e" : "#f59e0b"}`,
              color: modelOverview.learning.shadowCaptureEnabled ? "#86efac" : "#fcd34d",
              borderRadius: "999px",
              padding: "6px 12px",
              fontSize: "12px",
              fontWeight: "600",
            }}
          >
            {modelOverview.learning.shadowCaptureEnabled ? "Shadow Capture: Active" : "Shadow Capture: Paused"}
          </div>
          <div
            style={{
              border: `1px solid ${modelOverview.learning.autoTrainEnabled ? "#22c55e" : "#f59e0b"}`,
              color: modelOverview.learning.autoTrainEnabled ? "#86efac" : "#fcd34d",
              borderRadius: "999px",
              padding: "6px 12px",
              fontSize: "12px",
              fontWeight: "600",
            }}
          >
            {modelOverview.learning.autoTrainEnabled ? "Auto Train: Active" : "Auto Train: Paused"}
          </div>
          <div
            style={{
              border: `1px solid ${modelOverview.learning.liveDecisionSource === "shadow" ? "#a855f7" : "#0891b2"}`,
              color: modelOverview.learning.liveDecisionSource === "shadow" ? "#d8b4fe" : "#67e8f9",
              borderRadius: "999px",
              padding: "6px 12px",
              fontSize: "12px",
              fontWeight: "600",
            }}
          >
            Live Decisions: {modelOverview.learning.liveDecisionSource === "shadow" ? "Online Shadow" : "Production"}
          </div>
        </div>

        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "16px" }}>
          <button
            onClick={() => onShadowCaptureToggle(!modelOverview.learning.shadowCaptureEnabled)}
            style={{
              background: "rgba(34, 211, 238, 0.12)",
              color: "#67e8f9",
              border: "1px solid #0891b2",
              borderRadius: "10px",
              padding: "10px 14px",
              cursor: "pointer",
            }}
          >
            {modelOverview.learning.shadowCaptureEnabled ? "Pause Capture" : "Resume Capture"}
          </button>
          <button
            onClick={() => onAutoTrainToggle(!modelOverview.learning.autoTrainEnabled)}
            style={{
              background: "rgba(34, 197, 94, 0.12)",
              color: "#86efac",
              border: "1px solid #15803d",
              borderRadius: "10px",
              padding: "10px 14px",
              cursor: "pointer",
            }}
          >
            {modelOverview.learning.autoTrainEnabled ? "Pause Auto Train" : "Resume Auto Train"}
          </button>
          <button
            onClick={() => onLiveDecisionSourceChange("production")}
            style={{
              background: "rgba(34, 211, 238, 0.12)",
              color: "#67e8f9",
              border: "1px solid #0891b2",
              borderRadius: "10px",
              padding: "10px 14px",
              cursor: "pointer",
            }}
          >
            Use Production Decisions
          </button>
          <button
            onClick={() => onLiveDecisionSourceChange("shadow")}
            style={{
              background: "rgba(168, 85, 247, 0.12)",
              color: "#d8b4fe",
              border: "1px solid #7c3aed",
              borderRadius: "10px",
              padding: "10px 14px",
              cursor: "pointer",
            }}
          >
            Use Online Decisions
          </button>
          <button
            onClick={onRollbackShadow}
            style={{
              background: "rgba(248, 113, 113, 0.12)",
              color: "#fca5a5",
              border: "1px solid #b91c1c",
              borderRadius: "10px",
              padding: "10px 14px",
              cursor: "pointer",
            }}
          >
            Rollback Latest
          </button>
          <button
            onClick={onOpenReport}
            style={{
              background: "rgba(168, 85, 247, 0.12)",
              color: "#d8b4fe",
              border: "1px solid #7c3aed",
              borderRadius: "10px",
              padding: "10px 14px",
              cursor: "pointer",
            }}
          >
            Open Online Learning Report
          </button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px", marginBottom: "16px" }}>
          {learningStats.map((item) => (
            <div key={item.label} style={{ background: "#0f172a", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
              <div style={{ color: "#94a3b8", fontSize: "13px" }}>{item.label}</div>
              <div style={{ fontSize: "24px", fontWeight: "700", marginTop: "8px" }}>{item.value}</div>
            </div>
          ))}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px", marginBottom: "16px" }}>
          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
            <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Auto Train Policy</div>
            <div style={{ color: "#e2e8f0", fontSize: "13px", lineHeight: "1.7" }}>
              <div>
                <strong>Trigger:</strong> Start training when ready capacity reaches {scoreText(modelOverview.learning.autoTrainMinWeight)}
                {modelOverview.learning.autoTrainTailSingleSampleEnabled ? " or when one clean leftover sample remains" : ""}
              </div>
              <div>
                <strong>Minimum Batch:</strong> Need at least {modelOverview.learning.autoTrainMinBatchSamples} eligible samples before auto-train starts
                {modelOverview.learning.autoTrainTailSingleSampleEnabled ? " (tail batches may train the final clean sample on its own)" : ""}
              </div>
              <div><strong>Micro-Batch:</strong> Train up to {scoreText(modelOverview.learning.autoTrainBatchWeight)} learning capacity or {modelOverview.learning.autoTrainMaxBatchSamples} samples per cycle</div>
              <div><strong>Shadow Eval Guard:</strong> Need at least {modelOverview.learning.shadowEvalMinReferenceSamples} reference samples for full regression guard</div>
              <div><strong>Live Decision Source:</strong> {modelOverview.learning.liveDecisionSource === "shadow" ? "Online Shadow" : "Production"}</div>
              <div><strong>Switched At:</strong> {modelOverview.learning.lastDecisionSourceSwitchAt || "-"}</div>
              <div><strong>Last Auto Train:</strong> {modelOverview.learning.lastAutoTrainAt || "-"}</div>
              <div><strong>Last Trained Count:</strong> {modelOverview.learning.lastAutoTrainCount ?? 0}</div>
              <div><strong>Last Trained Capacity:</strong> {scoreText(modelOverview.learning.lastAutoTrainWeight)}</div>
            </div>
          </div>

          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
            <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Shadow Train Eval</div>
            <div style={{ color: "#e2e8f0", fontSize: "13px", lineHeight: "1.7" }}>
              <div>
                <strong>Status:</strong>{" "}
                <span style={{ color: getEvalStatusColor(modelOverview.learning.lastShadowEvalStatus), fontWeight: "700" }}>
                  {modelOverview.learning.lastShadowEvalStatus || "-"}
                </span>
              </div>
              <div><strong>Checked At:</strong> {modelOverview.learning.lastShadowEvalAt || "-"}</div>
              <div><strong>Reference Samples:</strong> {modelOverview.learning.lastShadowEvalReferenceSamples ?? 0}</div>
              <div><strong>Batch Samples:</strong> {modelOverview.learning.lastShadowEvalBatchSamples ?? 0}</div>
              <div style={{ marginTop: "6px" }}><strong>What Happened:</strong> {friendlyEvalReason(modelOverview.learning.lastShadowEvalStatus, modelOverview.learning.lastShadowEvalReason)}</div>
              <div style={{ marginTop: "6px" }}><strong>Last Rollback:</strong> {modelOverview.learning.lastRollbackAt || "-"}</div>
              <div style={{ marginTop: "6px" }}><strong>Rollback Reason:</strong> {modelOverview.learning.lastRollbackReason || "-"}</div>
            </div>
          </div>
        </div>

        <div style={{ marginBottom: "16px" }}>
          <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #334155", borderRadius: "14px", padding: "14px" }}>
            <div style={{ color: "#94a3b8", fontSize: "13px", marginBottom: "8px" }}>Sample Store</div>
            <div style={{ color: "#e2e8f0", fontSize: "13px", lineHeight: "1.6", wordBreak: "break-all" }}>
              {modelOverview.learning.storePath}
            </div>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "14px" }}>
          {renderSampleList(pendingSamples, "No pending samples right now.", "pending")}
          {renderSampleList(candidateSamples, "No review candidates are waiting right now.", "candidate")}
          {renderSampleList(readySamples, "No labeled samples waiting for training.", "ready")}
        </div>
      </div>
    </>
  );
}
