import json
import sys
from html import escape
from pathlib import Path
from typing import Optional

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_OUTPUT = REPORTS_DIR / "nidps_report_latest.html"
MALWARE_RULES = {"C2_BEACON", "DNS_TUNNEL", "DATA_EXFIL", "CRYPTO_MINER", "C2_BACKDOOR", "RANSOMWARE_PRECHECK"}
OBSERVED_RULES = {"OBS_PING", "OBS_SSH", "OBS_NMAP_SCAN"}


def pick_column(df: pd.DataFrame, *candidates: str) -> Optional[str]:
    for name in candidates:
        if name in df.columns:
            return name
    return None


def resolve_input_path(arg_path: Optional[str]) -> Path:
    if arg_path:
        path = Path(arg_path)
        if not path.is_absolute():
            path = (BASE_DIR / path).resolve()
        if path.exists():
            return path
        raise FileNotFoundError(f"File not found: {path}")

    candidates = [
        LOGS_DIR / "nidps_events.jsonl",
        LOGS_DIR / "nidps_events.csv",
        BASE_DIR / "nidps_events.jsonl",
        BASE_DIR / "nidps_events.csv",
    ]
    for path in candidates:
        if path.exists():
            return path

    log_dir = LOGS_DIR
    if log_dir.exists():
        jsonl_candidates = sorted(log_dir.glob("events_*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if jsonl_candidates:
            return jsonl_candidates[0]
        csv_candidates = sorted(log_dir.glob("events_*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        if csv_candidates:
            return csv_candidates[0]

    raise FileNotFoundError("No report input found. Expected nidps_events.jsonl/csv or logs/events_*.jsonl/csv")


def load_events(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".jsonl":
        rows = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return pd.DataFrame(rows)
    return pd.read_csv(path)


def fmt_int(value) -> str:
    try:
        return f"{int(float(value)):,}"
    except Exception:
        return "-"


def fmt_float(value, digits: int = 3) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except Exception:
        return "-"


def num_or_zero(value) -> float:
    try:
        if value is None:
            return 0.0
        return float(value)
    except Exception:
        return 0.0


def fmt_text(value) -> str:
    if value is None:
        return "-"
    text = str(value).strip()
    return text if text else "-"


def get_value(row: pd.Series, name: str, default=None):
    return row[name] if name in row and pd.notna(row[name]) else default


def infer_category(rule_value) -> str:
    rule = fmt_text(rule_value)
    if rule in OBSERVED_RULES:
        return "OBSERVED"
    if rule in MALWARE_RULES:
        return "MALWARE"
    return "ATTACK"


def format_attack_score(row: pd.Series) -> str:
    category = fmt_text(get_value(row, "category", infer_category(get_value(row, "rule", "-"))))
    if category == "OBSERVED":
        return "-"
    return fmt_float(get_value(row, "atk", ""))


def format_malware_score(row: pd.Series) -> str:
    category = fmt_text(get_value(row, "category", infer_category(get_value(row, "rule", "-"))))
    if category != "MALWARE":
        return "-"
    return fmt_float(get_value(row, "mal", ""))


def render_score_line(row: pd.Series) -> str:
    category = fmt_text(get_value(row, "category", infer_category(get_value(row, "rule", "-"))))
    if category == "OBSERVED":
        return "<strong>Traffic View</strong>: Observed traffic only (no AI scoring)"
    if category == "ATTACK":
        return f"<strong>Attack AI</strong>: {escape(format_attack_score(row))}"
    return f"<strong>Attack AI</strong>: {escape(format_attack_score(row))} | <strong>Malware AI</strong>: {escape(format_malware_score(row))}"


def render_stat_card(label: str, value: str, hint: str = "") -> str:
    hint_html = f'<div class="hint">{escape(hint)}</div>' if hint else ''
    return f'''<div class="card"><div class="label">{escape(label)}</div><div class="value">{escape(value)}</div>{hint_html}</div>'''


def render_kv_table(title: str, mapping: dict[str, str]) -> str:
    rows = []
    for key, value in mapping.items():
        rows.append(f"<tr><th>{escape(str(key))}</th><td>{escape(str(value))}</td></tr>")
    return f'''<section class="panel"><h2>{escape(title)}</h2><table class="kv">{''.join(rows)}</table></section>'''

def render_event_feed(df: pd.DataFrame) -> str:
    items = []
    for _, row in df.head(20).iterrows():
        ts = fmt_text(get_value(row, "ts", "-"))
        decision = fmt_text(get_value(row, "decision", "-"))
        rule = fmt_text(get_value(row, "rule", "-"))
        category = fmt_text(get_value(row, "category", infer_category(rule)))
        src = fmt_text(get_value(row, "src", "-"))
        src_mac = fmt_text(get_value(row, "src_mac", "-"))
        dst = fmt_text(get_value(row, "dst", "-"))
        dst_mac = fmt_text(get_value(row, "dst_mac", "-"))
        flows = fmt_int(get_value(row, "flows", 0))
        spkts = fmt_int(get_value(row, "spkts", 0))
        dpkts = fmt_int(get_value(row, "dpkts", 0))
        total_pkts = fmt_int(num_or_zero(get_value(row, "spkts", 0)) + num_or_zero(get_value(row, "dpkts", 0)))
        items.append(f'''
        <div class="feed-item">
            <div class="feed-head"><span class="badge">{escape(decision)}</span><span class="ts">{escape(ts)}</span></div>
            <div class="feed-rule">{escape(rule)}</div>
            <div class="feed-line"><strong>Category</strong>: {escape(category)}</div>
            <div class="feed-line"><strong>Source</strong>: {escape(src)} ({escape(src_mac)})</div>
            <div class="feed-line"><strong>Target</strong>: {escape(dst)} ({escape(dst_mac)})</div>
            <div class="feed-line"><strong>Flows</strong>: {escape(flows)} | <strong>Spkts</strong>: {escape(spkts)} | <strong>Dpkts</strong>: {escape(dpkts)} | <strong>Total Pkts</strong>: {escape(total_pkts)}</div>
            <div class="feed-line">{render_score_line(row)}</div>
        </div>
        ''')
    return ''.join(items)


def render_events_table(df: pd.DataFrame) -> str:
    rows = []
    for _, row in df.iterrows():
        total_pkts = num_or_zero(get_value(row, "spkts", 0)) + num_or_zero(get_value(row, "dpkts", 0))
        category = fmt_text(get_value(row, "category", infer_category(get_value(row, "rule", "-"))))
        rows.append(f'''
        <tr>
            <td>{escape(fmt_text(get_value(row, "ts", "-")))}</td>
            <td><span class="badge small">{escape(fmt_text(get_value(row, "decision", "-")))}</span></td>
            <td>{escape(category)}</td>
            <td>{escape(fmt_text(get_value(row, "rule", "-")))}</td>
            <td>{escape(fmt_text(get_value(row, "src", "-")))}</td>
            <td>{escape(fmt_text(get_value(row, "src_mac", "-")))}</td>
            <td>{escape(fmt_text(get_value(row, "dst", "-")))}</td>
            <td>{escape(fmt_text(get_value(row, "dst_mac", "-")))}</td>
            <td>{escape(fmt_int(get_value(row, "flows", 0)))}</td>
            <td>{escape(fmt_int(get_value(row, "spkts", 0)))}</td>
            <td>{escape(fmt_int(get_value(row, "dpkts", 0)))}</td>
            <td>{escape(fmt_int(total_pkts))}</td>
            <td>{escape(fmt_int(get_value(row, "sbytes", 0)))}</td>
            <td>{escape(fmt_int(get_value(row, "dbytes", 0)))}</td>
            <td>{escape(fmt_text(get_value(row, "proto", "-")))}</td>
            <td>{escape(fmt_text(get_value(row, "top_dport", "-")))}</td>
            <td>{escape(format_attack_score(row))}</td>
            <td>{escape(format_malware_score(row))}</td>
        </tr>
        ''')
    return ''.join(rows)


def generate_report(input_path: Optional[str] = None, output_path: Optional[str] = None) -> dict:
    source_path = resolve_input_path(input_path)
    df = load_events(source_path)

    if df.empty:
        html = """<html><body><h1>NIDPS Report</h1><p>No events found.</p></body></html>"""
        out_path = Path(output_path).resolve() if output_path else DEFAULT_OUTPUT
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
        return {"input_path": str(source_path), "output_path": str(out_path), "total_events": 0, "total_blocked": 0}

    ts_col = pick_column(df, "ts")
    rule_col = pick_column(df, "rule", "rule_type")
    src_col = pick_column(df, "src", "src_ip")
    decision_col = pick_column(df, "decision")
    atk_col = pick_column(df, "atk", "ai_attack_prob")
    mal_col = pick_column(df, "mal", "ai_malware_prob")

    missing = [
        name for name, col in (
            ("ts", ts_col),
            ("rule/rule_type", rule_col),
            ("src/src_ip", src_col),
            ("decision", decision_col),
        ) if col is None
    ]
    if missing:
        raise ValueError(f"Unsupported report schema. Missing columns: {', '.join(missing)}")

    df["ts"] = pd.to_datetime(df[ts_col], errors="coerce")
    df = df.dropna(subset=["ts"]).sort_values("ts", ascending=False).copy()

    rename_map = {}
    if rule_col != "rule":
        rename_map[rule_col] = "rule"
    if src_col != "src":
        rename_map[src_col] = "src"
    if decision_col != "decision":
        rename_map[decision_col] = "decision"
    if atk_col and atk_col != "atk":
        rename_map[atk_col] = "atk"
    if mal_col and mal_col != "mal":
        rename_map[mal_col] = "mal"
    if rename_map:
        df = df.rename(columns=rename_map)

    for col in ["category", "src_mac", "dst", "dst_mac", "flows", "spkts", "dpkts", "sbytes", "dbytes", "uniq_dports", "proto", "top_dport", "atk", "mal"]:
        if col not in df.columns:
            if col == "category":
                df[col] = df["rule"].apply(infer_category)
            else:
                df[col] = 0 if col in {"flows", "spkts", "dpkts", "sbytes", "dbytes", "uniq_dports", "atk", "mal"} else "-"

    df["category"] = df["category"].fillna(df["rule"].apply(infer_category))

    blocks = df[df["decision"].astype(str).str.startswith("BLOCKED")]
    observed = df[df["decision"].astype(str) == "OBSERVED"]
    top_rule = df["rule"].value_counts().idxmax() if not df.empty else "-"
    top_src = df["src"].value_counts().idxmax() if not df.empty else "-"
    latest_ts = df["ts"].max().strftime("%Y-%m-%d %H:%M:%S") if not df.empty else "-"
    total_packets = int(pd.to_numeric(df["spkts"], errors="coerce").fillna(0).sum() + pd.to_numeric(df["dpkts"], errors="coerce").fillna(0).sum())

    summary_cards = ''.join([
        render_stat_card("Total Events", fmt_int(len(df))),
        render_stat_card("Total Blocked", fmt_int(len(blocks))),
        render_stat_card("Observed Events", fmt_int(len(observed))),
        render_stat_card("Latest Event", latest_ts),
        render_stat_card("Top Rule", fmt_text(top_rule)),
        render_stat_card("Top Source", fmt_text(top_src)),
        render_stat_card("Total Packets Logged", fmt_int(total_packets)),
        render_stat_card("Block Policy", "Permanent"),
    ])

    top_rules = df["rule"].value_counts().head(8)
    top_sources = df["src"].value_counts().head(8)
    top_rule_map = {str(idx): fmt_int(val) for idx, val in top_rules.items()}
    top_source_map = {str(idx): fmt_int(val) for idx, val in top_sources.items()}
    html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIDPS Report</title>
<style>
:root {{
  --bg: #0f172a;
  --panel: #111827;
  --text: #e5e7eb;
  --muted: #94a3b8;
  --border: #334155;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: Segoe UI, Arial, sans-serif; background: linear-gradient(180deg, #0b1220 0%, #111827 100%); color: var(--text); }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
.hero {{ background: rgba(17,24,39,.92); border: 1px solid var(--border); border-radius: 20px; padding: 24px; margin-bottom: 20px; box-shadow: 0 20px 60px rgba(0,0,0,.28); }}
h1 {{ margin: 0 0 10px; font-size: 32px; }}
.sub {{ color: var(--muted); font-size: 14px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-top: 18px; }}
.card, .panel {{ background: rgba(17,24,39,.92); border: 1px solid var(--border); border-radius: 18px; box-shadow: 0 10px 30px rgba(0,0,0,.22); }}
.card {{ padding: 16px; }}
.label {{ color: var(--muted); font-size: 13px; margin-bottom: 8px; }}
.value {{ font-size: 26px; font-weight: 700; line-height: 1.1; }}
.hint {{ color: var(--muted); font-size: 12px; margin-top: 8px; }}
.two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-top: 20px; }}
.panel {{ padding: 18px; }}
h2 {{ margin: 0 0 14px; font-size: 20px; }}
.kv {{ width: 100%; border-collapse: collapse; }}
.kv th, .kv td {{ padding: 10px 0; border-bottom: 1px solid rgba(148,163,184,.16); text-align: left; }}
.kv th {{ color: var(--muted); width: 55%; font-weight: 600; }}
.feed {{ display: grid; gap: 12px; margin-top: 20px; }}
.feed-item {{ background: rgba(31,41,55,.72); border: 1px solid rgba(148,163,184,.15); border-radius: 16px; padding: 14px; }}
.feed-head {{ display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 8px; }}
.feed-rule {{ font-size: 18px; font-weight: 700; margin-bottom: 8px; }}
.feed-line {{ color: #dbeafe; margin-bottom: 4px; }}
.badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: rgba(34,197,94,.18); color: #bbf7d0; border: 1px solid rgba(34,197,94,.32); font-size: 12px; font-weight: 700; }}
.badge.small {{ font-size: 11px; padding: 3px 8px; }}
.ts {{ color: var(--muted); font-size: 12px; }}
.table-wrap {{ margin-top: 20px; overflow-x: auto; }}
table.events {{ width: 100%; border-collapse: collapse; min-width: 1280px; }}
.events th, .events td {{ padding: 10px 12px; border-bottom: 1px solid rgba(148,163,184,.14); text-align: left; vertical-align: top; }}
.events th {{ position: sticky; top: 0; background: #172033; color: #cbd5e1; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
.events tr:hover {{ background: rgba(51,65,85,.25); }}
.footer {{ color: var(--muted); font-size: 12px; margin-top: 20px; }}
@media (max-width: 960px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="container">
  <section class="hero">
    <h1>AI-NIDPS Report</h1>
    <div class="sub">Input log: {escape(str(source_path))} | Output file: {escape(str((Path(output_path).resolve() if output_path else DEFAULT_OUTPUT)))} | Updated: {escape(latest_ts)} | Block policy: Permanent</div>
    <div class="grid">{summary_cards}</div>
  </section>

  <div class="two-col">
    {render_kv_table("Top Event Rules", top_rule_map)}
    {render_kv_table("Top Source IPs", top_source_map)}
  </div>

  <section class="panel" style="margin-top:20px;">
    <h2>Readable Event Feed</h2>
    <div class="sub">Newest 20 events, including normal observed ping, SSH, and small Nmap-style traffic.</div>
    <div class="feed">{render_event_feed(df)}</div>
  </section>

  <section class="panel" style="margin-top:20px;">
    <h2>Full Event Table</h2>
    <div class="sub">This lists every observed or alert event with IP, MAC, rule, packets, bytes, category, AI score, and final action.</div>
    <div class="table-wrap">
      <table class="events">
        <thead>
          <tr>
            <th>Time</th><th>Decision</th><th>Category</th><th>Rule</th><th>Source IP</th><th>Source MAC</th><th>Target IP</th><th>Target MAC</th>
            <th>Flows</th><th>Spkts</th><th>Dpkts</th><th>Total Pkts</th><th>SBytes</th><th>DBytes</th><th>Proto</th><th>Top DPort</th><th>Attack AI</th><th>Malware AI</th>
          </tr>
        </thead>
        <tbody>
          {render_events_table(df)}
        </tbody>
      </table>
    </div>
  </section>

  <div class="footer">Single-file report generated by make_report.py. This report overwrites the previous latest report file by default to keep your project folder tidy.</div>
</div>
</body>
</html>
'''

    out_path = Path(output_path).resolve() if output_path else DEFAULT_OUTPUT
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return {
        "input_path": str(source_path),
        "output_path": str(out_path),
        "total_events": int(len(df)),
        "total_blocked": int(len(blocks)),
    }


def main() -> None:
    arg_path = sys.argv[1] if len(sys.argv) >= 2 else None
    out_path = sys.argv[2] if len(sys.argv) >= 3 else None
    try:
        result = generate_report(arg_path, out_path)
    except Exception as exc:
        print(f"Report generation failed: {exc}")
        sys.exit(1)

    print("Report generated:", result["output_path"])
    print("Input log:", result["input_path"])
    print("Total events:", result["total_events"])
    print("Total blocked:", result["total_blocked"])


if __name__ == "__main__":
    main()
