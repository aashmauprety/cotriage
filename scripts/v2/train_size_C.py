"""Setting C: how many labeled training networks do learned routing (P2) and the random forest need?

For k = 1, 2, 4, 7 training networks: every network is held out in turn and the learner is trained on
k networks drawn at random from the other seven; the test decisions of the eight networks are pooled
into one balanced accuracy. Repeated for DRAWS random draws (k = 7 has a single draw).
The LLM configurations without learning (S0, S4) need no labels and are shown for reference.

Usage: .venv/bin/python scripts/v2/train_size_C.py  ->  results/train_size_C.md
"""
import math
import os
import random
import sys
from collections import defaultdict

import numpy as np
from sklearn.ensemble import RandomForestClassifier

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze_C as C  # noqa: E402

DRAWS = 20
LAM = 0.05


def ba(decs):
    return C.score([d + (0.0, False) for d in decs])["ba"]


def route(model, run, conds, train, test_ids):
    base = sum(C.cost(model, run[c]["L0_none"]) for c in train) / len(train)
    by = defaultdict(list)
    for c in train:
        by[C.CASES[c]["desc"]].append(c)
    choice = {d: min(conds, key=lambda k: sum((C.said(run[c][k]) != run[c][k]["truth"]) + LAM * C.cost(model, run[c][k]) / base
                                             for c in cs)) for d, cs in by.items()}
    return [(C.said(run[c][choice.get(C.CASES[c]["desc"], "only_ip")]), C.CASES[c]["truth"]) for c in test_ids]


def main():
    ids = sorted(C.SAMPLE)
    by_scen = {s: [c for c in ids if C.CASES[c]["scenario"] == s] for s in C.SCENS}
    F = C.features(ids)
    descs = sorted({C.CASES[c]["desc"] for c in ids})
    X = {c: [math.log1p(F[c]["n"]), F[c]["level"], math.log1p(F[c]["other"]), F[c]["other_sigs"],
             math.log1p(F[c]["sig_rate"]), math.log1p(F[c]["pair_rate"]), F[c]["hour"], math.log1p(F[c]["burst"])]
         + [float(C.CASES[c]["desc"] == d) for d in descs] for c in ids}
    runs = {m: rs for m in C.PRICE if (rs := C.runs(m, set(ids)))}
    conds = {m: [k for k in C.CONDITIONS if all(k in rs[0][c] for c in rs[0])] for m, rs in runs.items()}
    rng = random.Random(0)
    res = defaultdict(list)
    for k in [1, 2, 4, 7]:
        for _ in range(1 if k == 7 else DRAWS):
            subsets = {t: rng.sample([s for s in C.SCENS if s != t], k) for t in C.SCENS}
            rf, p2 = [], defaultdict(list)
            for t, tr_s in subsets.items():
                train = [c for c in ids if C.CASES[c]["scenario"] in tr_s]  # same order as analyze_C
                if len({C.CASES[c]["truth"] for c in train}) < 2:
                    continue
                clf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
                clf.fit(np.array([X[c] for c in train]), [C.CASES[c]["truth"] for c in train])
                rf += list(zip(clf.predict(np.array([X[c] for c in by_scen[t]])).astype(bool),
                               [C.CASES[c]["truth"] for c in by_scen[t]]))
                for m, rs in runs.items():
                    for i, r in enumerate(rs):
                        p2[(m, i)] += route(m, r, conds[m], train, by_scen[t])
            res[("Random forest", k)].append(ba(rf))
            for m in runs:
                res[(f"{C.NAME[m]} P2 routing", k)].append(np.mean([ba(v) for (mm, _), v in p2.items() if mm == m]))
    L = ["# Setting C: balanced accuracy (%) vs. number of labeled training networks", "",
         f"Mean over {DRAWS} random draws of the training networks (min-max in parentheses); P2 lambda={LAM}.", "",
         "| method | 1 network | 2 networks | 4 networks | 7 networks |", "|---|---|---|---|---|"]
    for name in ["Random forest"] + [f"{C.NAME[m]} P2 routing" for m in runs if runs[m]]:
        cells = []
        for k in [1, 2, 4, 7]:
            v = res[(name, k)]
            cells.append(f"{np.mean(v):.1f} ({min(v):.1f}-{max(v):.1f})" if len(v) > 1 else f"{v[0]:.1f}")
        L.append(f"| {name} | " + " | ".join(cells) + " |")
    for m, rs in runs.items():
        for k, label in [("L0_none", "no tools"), ("L4_+host", "all tools")]:
            v = np.mean([ba([(C.said(r[c][k]), C.CASES[c]["truth"]) for c in ids]) for r in rs])
            L.append(f"| {C.NAME[m]} {label} (no labels) | {v:.1f} | {v:.1f} | {v:.1f} | {v:.1f} |")
    open(os.path.join(HERE, "..", "..", "results", "train_size_C.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
