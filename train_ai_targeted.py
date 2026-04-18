import json
import math
from pathlib import Path

import joblib
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
WINDOW_SEC = 30
RANDOM_STATE = 42

CSV_FILES = [
    BASE_DIR / "data" / "raw" / "UNSW-NB15_1.csv",
    BASE_DIR / "data" / "raw" / "UNSW-NB15_2.csv",
    BASE_DIR / "data" / "raw" / "UNSW-NB15_3.csv",
    BASE_DIR / "data" / "raw" / "UNSW-NB15_4.csv",
]
CURRENT_ATTACK_MODEL_PATH = MODELS_DIR / "model_attack.joblib"
EVENT_LOG_PATH = BASE_DIR / "logs" / "nidps_events.jsonl"
CANDIDATE_MODEL_PATH = MODELS_DIR / "model_attack_candidate.joblib"

UNSW_COLUMNS = [
    "srcip","sport","dstip","dsport","proto","state","dur",
    "sbytes","dbytes","sttl","dttl","sloss","dloss","service",
    "sload","dload","spkts","dpkts","swin","dwin","stcpb","dtcpb",
    "smeansz","dmeansz","trans_depth","res_bdy_len","sjit","djit",
    "stime","ltime","sintpkt","dintpkt","tcprtt","synack","ackdat",
    "is_sm_ips_ports","ct_state_ttl","ct_flw_http_mthd","is_ftp_login",
    "ct_ftp_cmd","ct_srv_src","ct_srv_dst","ct_dst_ltm","ct_src_ltm",
    "ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm",
    "attack_cat","label"
]

TARGET_RULES = {
    "PORT_SCAN",
    "ICMP_FLOOD",
    "SSH_BRUTE_FORCE", "FTP_BRUTE_FORCE", "TELNET_BRUTE_FORCE", "RDP_BRUTE_FORCE", "WINBOX_BRUTE_FORCE",
}
PRESERVE_RULES = {"TCP_FLOOD", "UDP_FLOOD", "HTTP_FLOOD"}
OBSERVED_RULES = {"OBS_PING", "OBS_SSH", "OBS_NMAP_SCAN", "OBS_UNKNOWN"}
POSITIVE_STRONG = {"BLOCKED", "ALREADY_BLOCKED_OR_NEVER"}
POSITIVE_WEAK = {"NOT_BLOCKED"}
RULE_THRESHOLDS = {
    "PORT_SCAN": 0.60,
    "ICMP_FLOOD": 0.55,
    "SSH_BRUTE_FORCE": 0.50,
    "FTP_BRUTE_FORCE": 0.50,
    "TELNET_BRUTE_FORCE": 0.50,
    "RDP_BRUTE_FORCE": 0.50,
    "WINBOX_BRUTE_FORCE": 0.50,
    "TCP_FLOOD": 0.72,
    "UDP_FLOOD": 0.72,
    "HTTP_FLOOD": 0.72,
}
TRACK_RULES = [
    "PORT_SCAN",
    "ICMP_FLOOD",
    "SSH_BRUTE_FORCE",
    "WINBOX_BRUTE_FORCE",
    "TCP_FLOOD",
    "UDP_FLOOD",
    "HTTP_FLOOD",
]


def entropy(values):
    total = sum(values)
    if total == 0:
        return 0.0
    e = 0.0
    for v in values:
        p = v / total
        if p > 0:
            e -= p * math.log2(p)
    return e


def _to_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return float(default)


def load_model_bundle(path):
    obj = joblib.load(path)
    return obj["model"], list(obj["feature_columns"])


def build_window_features(df):
    numeric_cols = ["dsport", "spkts", "dpkts", "sbytes", "dbytes", "proto", "stime", "label"]

    for c in numeric_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    df["window"] = (df["stime"] // WINDOW_SEC).astype(int)
    groups = df.groupby(["srcip", "dstip", "window"])

    rows = []
    for (_src, _dst, _win), g in groups:
        flows = len(g)
        if flows < 5:
            continue

        Spkts = g["spkts"].sum()
        Dpkts = g["dpkts"].sum()
        sbytes = g["sbytes"].sum()
        dbytes = g["dbytes"].sum()

        uniq_dports = g["dsport"].nunique()
        proto_mode = g["proto"].mode().iloc[0] if not g["proto"].mode().empty else 0

        dport_counts = g["dsport"].value_counts()
        top_port = int(dport_counts.index[0])
        top_cnt = int(dport_counts.iloc[0])
        total = flows

        rows.append({
            "dur_sum": WINDOW_SEC,
            "flows": flows,
            "uniq_dports": uniq_dports,
            "proto_mode": proto_mode,
            "Spkts": Spkts,
            "Dpkts": Dpkts,
            "sbytes": sbytes,
            "dbytes": dbytes,
            "pkts_rate": (Spkts + Dpkts) / WINDOW_SEC,
            "bytes_rate": (sbytes + dbytes) / WINDOW_SEC,
            "sbytes_per_pkt": sbytes / (Spkts + 1),
            "dbytes_per_pkt": dbytes / (Dpkts + 1),
            "flow_ratio": Spkts / (Dpkts + 1),
            "byte_ratio": sbytes / (dbytes + 1),
            "top_port_ratio": top_cnt / total,
            "well_known_ratio": (g["dsport"] <= 1024).sum() / total,
            "high_port_ratio": (g["dsport"] >= 49152).sum() / total,
            "dport_entropy": entropy(dport_counts.values),
            "top_is_22": 1.0 if top_port == 22 else 0.0,
            "top_is_53": 1.0 if top_port == 53 else 0.0,
            "top_is_80": 1.0 if top_port == 80 else 0.0,
            "top_is_443": 1.0 if top_port == 443 else 0.0,
            "top_is_445": 1.0 if top_port == 445 else 0.0,
            "top_is_8291": 1.0 if top_port == 8291 else 0.0,
            "top_is_well_known": 1.0 if top_port <= 1024 else 0.0,
            "top_is_registered": 1.0 if 1025 <= top_port <= 49151 else 0.0,
            "top_is_dynamic": 1.0 if top_port >= 49152 else 0.0,
            "icmp_is_proto": 1.0 if proto_mode == 1 else 0.0,
            "icmp_pkt_per_flow": Spkts / (flows + 1),
            "attack_label": 1 if g["label"].max() == 1 else 0,
        })

    return pd.DataFrame(rows)


def build_event_frame(feature_columns):
    rows = []
    with EVENT_LOG_PATH.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            rule = str(payload.get("rule") or "").strip()
            decision = str(payload.get("decision") or "").strip()
            if not rule:
                continue

            label = None
            weight_kind = ""
            if rule in OBSERVED_RULES:
                label = 0
                weight_kind = "observed"
            elif rule in TARGET_RULES:
                if decision in POSITIVE_STRONG:
                    label = 1
                    weight_kind = "target_strong"
                elif decision in POSITIVE_WEAK:
                    label = 1
                    weight_kind = "target_weak"
            elif rule in PRESERVE_RULES and decision in POSITIVE_STRONG:
                label = 1
                weight_kind = "preserve"

            if label is None:
                continue

            flows = max(_to_float(payload.get("flows")), 1.0)
            uniq_dports = max(_to_float(payload.get("uniq_dports")), 1.0)
            top_port = int(_to_float(payload.get("top_dport")))
            top_slot = max(min(flows, uniq_dports), 1.0)
            row = {
                "dur_sum": WINDOW_SEC,
                "flows": flows,
                "uniq_dports": uniq_dports,
                "proto_mode": _to_float(payload.get("proto")),
                "Spkts": _to_float(payload.get("spkts")),
                "Dpkts": _to_float(payload.get("dpkts")),
                "sbytes": _to_float(payload.get("sbytes")),
                "dbytes": _to_float(payload.get("dbytes")),
                "pkts_rate": (_to_float(payload.get("spkts")) + _to_float(payload.get("dpkts"))) / WINDOW_SEC,
                "bytes_rate": (_to_float(payload.get("sbytes")) + _to_float(payload.get("dbytes"))) / WINDOW_SEC,
                "sbytes_per_pkt": _to_float(payload.get("sbytes")) / (_to_float(payload.get("spkts")) + 1.0),
                "dbytes_per_pkt": _to_float(payload.get("dbytes")) / (_to_float(payload.get("dpkts")) + 1.0),
                "flow_ratio": _to_float(payload.get("spkts")) / (_to_float(payload.get("dpkts")) + 1.0),
                "byte_ratio": _to_float(payload.get("sbytes")) / (_to_float(payload.get("dbytes")) + 1.0),
                "top_port_ratio": 1.0 / top_slot,
                "well_known_ratio": 1.0 if top_port <= 1024 else 0.0,
                "high_port_ratio": 1.0 if top_port >= 49152 else 0.0,
                "dport_entropy": math.log2(top_slot) if top_slot > 1.0 else 0.0,
                "top_is_22": 1.0 if top_port == 22 else 0.0,
                "top_is_53": 1.0 if top_port == 53 else 0.0,
                "top_is_80": 1.0 if top_port == 80 else 0.0,
                "top_is_443": 1.0 if top_port == 443 else 0.0,
                "top_is_445": 1.0 if top_port == 445 else 0.0,
                "top_is_8291": 1.0 if top_port == 8291 else 0.0,
                "top_is_well_known": 1.0 if top_port <= 1024 else 0.0,
                "top_is_registered": 1.0 if 1025 <= top_port <= 49151 else 0.0,
                "top_is_dynamic": 1.0 if top_port >= 49152 else 0.0,
                "icmp_is_proto": 1.0 if int(_to_float(payload.get("proto"))) == 1 else 0.0,
                "icmp_pkt_per_flow": _to_float(payload.get("spkts")) / (flows + 1.0),
                "attack_label": label,
                "rule": rule,
                "decision": decision,
                "weight_kind": weight_kind,
            }
            rows.append(row)

    frame = pd.DataFrame(rows)
    frame = frame.reindex(columns=feature_columns + ["attack_label", "rule", "decision", "weight_kind"], fill_value=0.0)
    split_key = frame["rule"].where(frame["attack_label"] == 1, other="NEG")
    train_frame, test_frame = train_test_split(
        frame,
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=split_key,
    )
    return train_frame.reset_index(drop=True), test_frame.reset_index(drop=True)


def heuristic_target_mask(frame):
    return (
        ((frame["uniq_dports"] >= 25) & (frame["top_port_ratio"] <= 0.25))
        | (((frame["top_is_22"] == 1.0) | (frame["top_is_8291"] == 1.0)) & (frame["flows"] >= 5) & (frame["uniq_dports"] <= 3))
        | ((frame["icmp_is_proto"] == 1.0) & (frame["Spkts"] >= 300))
    )


def heuristic_preserve_mask(frame):
    return (
        (((frame["top_is_80"] == 1.0) | (frame["top_is_443"] == 1.0)) & (frame["flows"] >= 120))
        | ((frame["proto_mode"] == 6.0) & (frame["flows"] >= 160) & (frame["uniq_dports"] <= 3))
        | ((frame["proto_mode"] == 17.0) & (frame["flows"] >= 180) & (frame["uniq_dports"] <= 5))
    )


def assign_base_weights(frame):
    weights = pd.Series(1.0, index=frame.index, dtype=float)
    attack_mask = frame["attack_label"] == 1
    weights.loc[attack_mask & heuristic_target_mask(frame)] += 0.35
    weights.loc[attack_mask & heuristic_preserve_mask(frame)] += 0.20
    return weights


def assign_event_weights(frame, target_weight, weak_target_weight, observed_weight, preserve_weight):
    weights = pd.Series(1.0, index=frame.index, dtype=float)
    weights.loc[frame["weight_kind"] == "target_strong"] = target_weight
    weights.loc[frame["weight_kind"] == "target_weak"] = weak_target_weight
    weights.loc[frame["weight_kind"] == "observed"] = observed_weight
    weights.loc[frame["weight_kind"] == "preserve"] = preserve_weight
    return weights


def predict_scores(model, feature_columns, frame):
    return model.predict_proba(frame[feature_columns])[:, 1]


def pass_rate(frame, probs, rule):
    subset = frame[(frame["rule"] == rule) & (frame["attack_label"] == 1)]
    if subset.empty:
        return None
    threshold = RULE_THRESHOLDS[rule]
    return float((probs[subset.index] >= threshold).mean())


def observed_fpr(frame, probs):
    subset = frame[frame["attack_label"] == 0]
    if subset.empty:
        return None
    return float((probs[subset.index] >= 0.50).mean())


def continue_train(base_model, feature_columns, train_frame, weights, extra_rounds):
    params = base_model.get_params()
    model = xgb.XGBClassifier(
        n_estimators=extra_rounds,
        max_depth=int(params.get("max_depth") or 8),
        learning_rate=float(params.get("learning_rate") or 0.05),
        subsample=float(params.get("subsample") or 0.9),
        colsample_bytree=float(params.get("colsample_bytree") or 0.9),
        tree_method=params.get("tree_method") or "hist",
        random_state=int(params.get("random_state") or RANDOM_STATE),
        n_jobs=int(params.get("n_jobs") or 16),
        objective=params.get("objective") or "binary:logistic",
        eval_metric="logloss",
    )
    model.fit(train_frame[feature_columns], train_frame["attack_label"], sample_weight=weights, xgb_model=base_model.get_booster())
    return model


def score_candidate(metrics):
    hard_fail = False
    for rule in PRESERVE_RULES:
        value = metrics.get(rule)
        if value is None or value < 1.0:
            hard_fail = True
    score = 0.0
    if hard_fail:
        score -= 100.0
    for rule in ["PORT_SCAN", "ICMP_FLOOD", "SSH_BRUTE_FORCE", "WINBOX_BRUTE_FORCE"]:
        value = metrics.get(rule)
        if value is not None:
            score += value * 10.0
    if metrics.get("observed_fpr") is not None:
        score -= metrics["observed_fpr"] * 5.0
    return score


def main():
    current_model, feature_columns = load_model_bundle(CURRENT_ATTACK_MODEL_PATH)

    dfs = []
    for path in CSV_FILES:
        print("Loading:", path)
        df = pd.read_csv(path, header=None, low_memory=False)
        df.columns = UNSW_COLUMNS
        dfs.append(df)
    unsw = pd.concat(dfs, ignore_index=True)
    feature_frame = build_window_features(unsw)
    feature_frame = feature_frame.reindex(columns=feature_columns + ["attack_label"], fill_value=0.0)

    base_train, base_test = train_test_split(
        feature_frame,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=feature_frame["attack_label"],
    )
    base_train = base_train.reset_index(drop=True)
    base_test = base_test.reset_index(drop=True)
    base_weights = assign_base_weights(base_train)

    event_train, event_test = build_event_frame(feature_columns)
    current_event_probs = predict_scores(current_model, feature_columns, event_test)

    current_metrics = {rule: pass_rate(event_test, current_event_probs, rule) for rule in TRACK_RULES}
    current_metrics["observed_fpr"] = observed_fpr(event_test, current_event_probs)
    print("Current holdout metrics:", current_metrics)

    configs = [
        {"extra_rounds": 20, "target_weight": 1.50, "weak_target_weight": 1.10, "observed_weight": 1.50, "preserve_weight": 1.20},
        {"extra_rounds": 20, "target_weight": 1.75, "weak_target_weight": 1.20, "observed_weight": 1.75, "preserve_weight": 1.20},
        {"extra_rounds": 40, "target_weight": 1.50, "weak_target_weight": 1.10, "observed_weight": 1.75, "preserve_weight": 1.25},
        {"extra_rounds": 40, "target_weight": 1.75, "weak_target_weight": 1.20, "observed_weight": 1.75, "preserve_weight": 1.30},
    ]

    best = None
    for cfg in configs:
        event_weights = assign_event_weights(
            event_train,
            target_weight=cfg["target_weight"],
            weak_target_weight=cfg["weak_target_weight"],
            observed_weight=cfg["observed_weight"],
            preserve_weight=cfg["preserve_weight"],
        )
        tune_train = pd.concat(
            [base_train[feature_columns + ["attack_label"]], event_train[feature_columns + ["attack_label", "rule", "decision", "weight_kind"]]],
            ignore_index=True,
        )
        tune_weights = pd.concat([base_weights.reset_index(drop=True), event_weights.reset_index(drop=True)], ignore_index=True)
        model = continue_train(current_model, feature_columns, tune_train, tune_weights, cfg["extra_rounds"])

        event_probs = predict_scores(model, feature_columns, event_test)
        base_probs = predict_scores(model, feature_columns, base_test)
        metrics = {rule: pass_rate(event_test, event_probs, rule) for rule in TRACK_RULES}
        metrics["observed_fpr"] = observed_fpr(event_test, event_probs)
        metrics["base_fpr"] = float(((base_probs >= 0.50) & (base_test["attack_label"] == 0)).sum()) / float((base_test["attack_label"] == 0).sum())
        metrics["score"] = score_candidate(metrics)
        print("Candidate config:", cfg)
        print("Candidate metrics:", metrics)
        if best is None or metrics["score"] > best["metrics"]["score"]:
            best = {"config": cfg, "metrics": metrics, "model": model}

    if best is None:
        raise RuntimeError("No candidate models were trained")

    print("Best config:", best["config"])
    print("Best metrics:", best["metrics"])
    joblib.dump({"model": best["model"], "feature_columns": feature_columns}, CANDIDATE_MODEL_PATH)
    print("Saved:", CANDIDATE_MODEL_PATH)


if __name__ == "__main__":
    main()
