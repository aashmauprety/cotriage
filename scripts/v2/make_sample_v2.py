"""Evaluation sample for Setting C: every malicious case plus a stratified benign sample per scenario.

Half of the benign cases of a scenario come from "ambiguous" alert types (alert descriptions that
also occur in malicious cases in any scenario), half from all other benign cases. A second,
disjoint benign sample (different seed) is written for the sensitivity analysis.
Malicious cases of one (scenario, alert type) are capped so that no single attack step dominates.

Usage: python3 -I scripts/v2/make_sample_v2.py [--benign-per-scenario 250] [--cap 20]
  -> alerts_v2/sample_C.txt (malicious + benign sample 1), alerts_v2/sample_C_benign2.txt
"""
import argparse
import glob
import json
import os
import random
from collections import defaultdict

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign-per-scenario", type=int, default=250)
    ap.add_argument("--cap", type=int, default=20)
    args = ap.parse_args()
    cases = [json.loads(l) for p in sorted(glob.glob(os.path.join(BASE, "alerts_v2", "cases_*.jsonl"))) for l in open(p)]
    mal_desc = {c["desc"] for c in cases if c["truth"]}
    rng = random.Random(7)
    mal, ben1, ben2 = [], [], []
    by = defaultdict(list)
    for c in cases:
        if c["truth"]:
            by[(c["scenario"], c["desc"])].append(c)
    for k in sorted(by):
        cs = by[k]
        mal += cs if len(cs) <= args.cap else rng.sample(cs, args.cap)
    for scen in sorted({c["scenario"] for c in cases}):
        b = [c for c in cases if c["scenario"] == scen and not c["truth"]]
        amb = [c for c in b if c["desc"] in mal_desc]
        rest = [c for c in b if c["desc"] not in mal_desc]
        rng.shuffle(amb)
        rng.shuffle(rest)
        h = args.benign_per_scenario // 2
        n_amb = min(h, len(amb) // 2)
        n_rest = args.benign_per_scenario - n_amb
        ben1 += amb[:n_amb] + rest[:n_rest]
        ben2 += amb[n_amb:2 * n_amb] + rest[n_rest:2 * n_rest]
    with open(os.path.join(BASE, "alerts_v2", "sample_C.txt"), "w") as f:
        f.write("\n".join(c["case_id"] for c in mal + ben1) + "\n")
    with open(os.path.join(BASE, "alerts_v2", "sample_C_benign2.txt"), "w") as f:
        f.write("\n".join(c["case_id"] for c in ben2) + "\n")
    print(f"malicious {len(mal)} (of {sum(c['truth'] for c in cases)}), benign sample 1: {len(ben1)}, "
          f"benign sample 2: {len(ben2)}, all cases {len(cases)}")
    per = defaultdict(lambda: [0, 0])
    for c in mal:
        per[c["scenario"]][0] += 1
    for c in ben1:
        per[c["scenario"]][1] += 1
    for s, (m, b) in sorted(per.items()):
        print(f"  {s:16s} malicious {m:4d}  benign {b:4d}")


if __name__ == "__main__":
    main()
