"""Step 5: accuracy / cost / ROI across settings, models and tool conditions.

Settings
  A    real Suricata alert cases (all 589 cases, triage.py)
  B30  vague "Suspicious behaviour" alerts, 30-minute look-back (triage_vague.py)
  B5   the same alerts, 5-minute look-back
Per (setting, model, condition), averaged over repeated runs:
  recall (attacks caught), false-positive rate, balanced accuracy = (TPR + TNR) / 2,
  API cost per 1,000 alerts (local qwen: $0, latency reported instead),
  and for each ladder step the gain in balanced accuracy per extra $ per 1,000 alerts.
A failed answer counts as "malicious" (escalated to a human).

Usage: .venv/bin/python scripts/roi_analysis.py   ->  results/summary.csv, results/tables.md, figures/*.png
"""
import csv
import glob
import json
import os
from collections import defaultdict

from summarize_triage import PRICES

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT = os.path.join(BASE, "outputs")
MODELS = {"qwen2.5_14b": "qwen2.5-14B (local)", "claude-haiku-5-5": "Claude Haiku 5.5",
          "claude-opus-5-5": "Claude Opus 5.5"}
SETTINGS = {
    "A": ("triage_{m}*.jsonl", ["L0_none", "L1_history", "L2_+suricata", "L3_+ip", "L4_+audit"],
          None),  # all 589 cases (was the 175-case sample alerts/sample_claude.txt)
    "B30": ("vague30_{m}*.jsonl", ["V0_none", "V1_overview", "V2_+suricata", "V3_+ip", "V4_+audit"], None),
    "B5": ("vague5_{m}*.jsonl", ["V0_none", "V1_overview", "V2_+suricata", "V3_+ip", "V4_+audit"], None),
}
SINGLES = ["only_suricata", "only_ip", "only_audit"]
STEP_NAMES = ["none", "+1st tool", "+2nd", "+3rd", "+4th (audit)"]


def metrics(rows, price):
    att = [r for r in rows if r["truth"]]
    ben = [r for r in rows if not r["truth"]]
    said = lambda r: (r["verdict"] or "malicious") == "malicious"
    tpr = sum(map(said, att)) / len(att)
    fpr = sum(map(said, ben)) / len(ben)
    cost = sum((r["prompt_tokens"] or 0) * price[0] + (r["output_tokens"] or 0) * price[1] for r in rows) / len(rows)
    secs = sum(r["llm_seconds"] + r["tool_seconds"] for r in rows) / len(rows)
    return {"recall": tpr, "fpr": fpr, "bal_acc": (tpr + 1 - fpr) / 2,
            "caught": sum(map(said, att)), "n_att": len(att),
            "false_alarms": sum(map(said, ben)), "n_ben": len(ben),
            "cost_per_1k": cost * 1000, "secs": secs}


def load(setting, model_key):
    pattern, conds, case_file = SETTINGS[setting]
    keep = {l.strip() for l in open(case_file) if l.strip()} if case_file else None
    runs = []
    for path in sorted(glob.glob(os.path.join(OUT, pattern.format(m=model_key)))):
        by = defaultdict(list)
        for r in map(json.loads, open(path)):
            if keep is None or r["case_id"] in keep:
                by[r["condition"]].append(r)
        # a run counts only if it covers every case for the conditions it has
        if by and len({len(v) for v in by.values()}) == 1:
            runs.append(by)
    return runs


def main():
    os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
    rows = []
    for setting, (_, ladder, _) in SETTINGS.items():
        for mk, mname in MODELS.items():
            runs = load(setting, mk)
            if not runs:
                continue
            price = PRICES.get(runs[0][next(iter(runs[0]))][0]["model"], (0.0, 0.0))
            for cond in ladder + SINGLES:
                per = [metrics(run[cond], price) for run in runs if cond in run]
                if not per:
                    continue
                avg = {k: sum(p[k] for p in per) / len(per) for k in per[0]}
                rows.append({"setting": setting, "model": mname, "condition": cond,
                             "step": ladder.index(cond) if cond in ladder else None,
                             "runs": len(per), **avg,
                             "recall_min": min(p["recall"] for p in per),
                             "recall_max": max(p["recall"] for p in per)})

    # ROI of each ladder step: balanced-accuracy points gained per extra $ per 1k alerts
    for r in rows:
        r["roi_pp_per_dollar"] = None
        if r["step"]:
            prev = next(x for x in rows if x["setting"] == r["setting"] and x["model"] == r["model"]
                        and x["step"] == r["step"] - 1)
            d_cost = r["cost_per_1k"] - prev["cost_per_1k"]
            d_acc = (r["bal_acc"] - prev["bal_acc"]) * 100
            r["gain_pp"] = d_acc
            r["extra_cost_per_1k"] = d_cost
            r["roi_pp_per_dollar"] = d_acc / d_cost if d_cost > 0.01 else None

    with open(os.path.join(BASE, "results", "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
        w.writeheader()
        w.writerows(rows)

    lines = ["# Results: alert triage with tool ladders", "",
             "Balanced accuracy = (attacks caught rate + correct-normal rate) / 2. "
             "Cost = API cost per 1,000 alerts (qwen runs locally: $0). "
             "Values are means over repeated runs where available (column `runs`).", ""]
    for setting in SETTINGS:
        sub = [r for r in rows if r["setting"] == setting]
        if not sub:
            continue
        n_att, n_ben = int(sub[0]["n_att"]), int(sub[0]["n_ben"])
        lines += [f"## Setting {setting} ({n_att} attack / {n_ben} normal alerts)", "",
                  "| model | condition | runs | caught | false alarms | balanced acc. | $ per 1k alerts | s/alert | step gain (pp) | pp per extra $ |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for r in sub:
            gain = f"{r['gain_pp']:+.1f}" if r.get("gain_pp") is not None else ""
            roi = (f"{r['roi_pp_per_dollar']:.1f}" if r["roi_pp_per_dollar"] is not None
                   else "≈ free" if r.get("gain_pp", 0) > 0 else "")
            lines.append(f"| {r['model']} | {r['condition']} | {r['runs']} | {r['caught']:.1f}/{int(r['n_att'])} | "
                         f"{r['false_alarms']:.1f}/{int(r['n_ben'])} | {r['bal_acc']:.3f} | {r['cost_per_1k']:.2f} | "
                         f"{r['secs']:.1f} | {gain} | {roi} |")
        lines.append("")
    open(os.path.join(BASE, "results", "tables.md"), "w").write("\n".join(lines))
    print("\n".join(lines))

    import figures
    figures.make(rows, SETTINGS, MODELS)


if __name__ == "__main__":
    main()
