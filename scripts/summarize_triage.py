"""Summarize alert-triage results per condition: attacks caught, false alarms,
cost, and the gain of each ladder step over the previous one.

A failed answer (refusal or unreadable reply) counts as "malicious" (escalated to
a human), the safe default for a triage system; failures are counted separately.

Usage: python3 scripts/summarize_triage.py outputs/triage_claude-opus-5-5.jsonl \
           [--case-file alerts/sample_claude.txt]
"""
import argparse
import json
from collections import defaultdict

PRICES = {"claude-opus-5-5": (4e-6, 20e-6), "claude-haiku-5-5": (0.1e-6, 0.5e-6), "claude-haiku-4-5": (1e-6, 5e-6)}  # $/token in, out; local models are free
# setting A (real Suricata alert cases) and setting B (vague alerts, triage_vague.py)
LADDER = ["L0_none", "L1_history", "L2_+suricata", "L3_+ip", "L4_+audit",
          "V0_none", "V1_overview", "V2_+suricata", "V3_+ip", "V4_+audit"]
SINGLES = ["only_suricata", "only_ip", "only_audit"]


def stats(rows, price):
    att = [r for r in rows if r["truth"]]
    ben = [r for r in rows if not r["truth"]]
    said = lambda r: (r["verdict"] or "malicious") == "malicious"
    tin = sum(r["prompt_tokens"] or 0 for r in rows)
    tout = sum(r["output_tokens"] or 0 for r in rows)
    n = len(rows) or 1
    return {
        "caught": sum(map(said, att)), "n_att": len(att),
        "false_alarms": sum(map(said, ben)), "n_ben": len(ben),
        "right": sum(said(r) == r["truth"] for r in rows), "n": len(rows),
        "failed": sum(r["verdict"] is None for r in rows),
        "cost": (tin * price[0] + tout * price[1]) / n,
        "tokens": (tin + tout) / n,
        "secs": sum(r["llm_seconds"] + r["tool_seconds"] for r in rows) / n,
    }


def table(title, by_cond, conds, price):
    print(f"\n{title}")
    print(f"{'condition':15s} {'caught':>9s} {'false alarms':>13s} {'right':>9s} {'fail':>5s} "
          f"{'tokens':>7s} {'$/case':>8s} {'s/case':>7s}  step gain")
    prev = None
    for c in conds:
        if c not in by_cond:
            continue
        s = stats(by_cond[c], price)
        gain = ""
        if prev and c in LADDER:
            d_right = s["right"] - prev["right"]
            d_cost = s["cost"] - prev["cost"]
            gain = f"{d_right:+d} right for {d_cost:+.4f} $/case"
        print(f"{c:15s} {s['caught']:4d}/{s['n_att']:<4d} {s['false_alarms']:6d}/{s['n_ben']:<6d} "
              f"{s['right']:4d}/{s['n']:<4d} {s['failed']:5d} {s['tokens']:7.0f} {s['cost']:8.4f} "
              f"{s['secs']:7.1f}  {gain}")
        if c in LADDER:
            prev = s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--case-file", help="only cases listed in this file")
    args = ap.parse_args()
    rows = [json.loads(l) for l in open(args.path)]
    if args.case_file:
        keep = {l.strip() for l in open(args.case_file) if l.strip()}
        rows = [r for r in rows if r["case_id"] in keep]
    model = rows[0]["model"]
    price = PRICES.get(model, (0.0, 0.0))

    vague = rows[0]["condition"].startswith("V") or "anchor_phase" in rows[0]
    hard_desc = ("quiet attack steps: upload, mail-curl, webshell" if vague
                 else "policy alarms: same alarm for attackers and users")
    groups = {"all cases": rows,
              f"HARD cases ({hard_desc})": [r for r in rows if r["hard"]],
              "EASY cases (everything else)": [r for r in rows if not r["hard"]]}
    n_cases = len({r["case_id"] for r in rows})
    print(f"=== {model}: {n_cases} cases")
    for title, rs in groups.items():
        by_cond = defaultdict(list)
        for r in rs:
            by_cond[r["condition"]].append(r)
        if by_cond:
            table(title, by_cond, LADDER + SINGLES, price)
    total = sum(r["prompt_tokens"] * price[0] + r["output_tokens"] * price[1] for r in rows)
    print(f"\ntotal cost ${total:.2f} for {len(rows)} calls; "
          f"refusals {sum(r['stop_reason'] == 'refusal' for r in rows)}")


if __name__ == "__main__":
    main()
