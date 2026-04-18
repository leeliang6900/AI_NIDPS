import math
from pathlib import Path

import joblib
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

BASE_DIR = Path(__file__).resolve().parent
DATA_RAW_DIR = BASE_DIR / "data" / "raw"
MODELS_DIR = BASE_DIR / "models"

WINDOW_SEC = 30
RANDOM_STATE = 42

CSV_FILES = [
    "data/raw/UNSW-NB15_1.csv",
    "data/raw/UNSW-NB15_2.csv",
    "data/raw/UNSW-NB15_3.csv",
    "data/raw/UNSW-NB15_4.csv",
]

ATTACK_MODEL_NAME = MODELS_DIR / "model_attack.joblib"

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


def build_window_features(df):
    numeric_cols = [
        "dsport", "spkts", "dpkts", "sbytes", "dbytes", "proto", "stime", "label"
    ]

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

        icmp_is_proto = 1.0 if proto_mode == 1 else 0.0
        icmp_pkt_per_flow = Spkts / (flows + 1)

        row = {
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
            "icmp_is_proto": icmp_is_proto,
            "icmp_pkt_per_flow": icmp_pkt_per_flow,
            "attack_label": 1 if g["label"].max() == 1 else 0,
        }
        rows.append(row)

    return pd.DataFrame(rows)


def main():
    dfs = []
    for f in CSV_FILES:
        csv_path = BASE_DIR / f
        print("Loading:", csv_path)
        df = pd.read_csv(csv_path, header=None, low_memory=False)
        df.columns = UNSW_COLUMNS
        dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    print("Total rows:", len(df))

    print("Building window features...")
    feat = build_window_features(df)
    print("Window samples:", len(feat))

    ps_ssh_mask = (
        (feat["uniq_dports"] > 20) |
        ((feat["top_is_22"] == 1) & (feat["flows"] > 15))
    )
    ps_ssh_attack = feat[ps_ssh_mask & (feat["attack_label"] == 1)]

    BOOST_FACTOR = 3
    boosted = pd.concat([ps_ssh_attack] * BOOST_FACTOR, ignore_index=True)
    feat_boosted = pd.concat([feat, boosted], ignore_index=True)

    X = feat_boosted.drop(columns=["attack_label"])
    y_attack = feat_boosted["attack_label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_attack,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y_attack
    )

    model = xgb.XGBClassifier(
        n_estimators=900,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        tree_method="hist",
        random_state=RANDOM_STATE,
        n_jobs=16,
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n=== Model:", ATTACK_MODEL_NAME, "===")
    print(classification_report(y_test, y_pred, digits=4))
    print("ROC-AUC:", roc_auc_score(y_test, y_prob))

    Path(ATTACK_MODEL_NAME).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model,
        "feature_columns": list(X.columns)
    }, ATTACK_MODEL_NAME)

    print("Saved:", ATTACK_MODEL_NAME)
    print("Malware training is intentionally not done here. Use train_malware.py for model_malware.joblib.")


if __name__ == "__main__":
    main()
