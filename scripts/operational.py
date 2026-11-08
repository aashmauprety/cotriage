"""Operational metrics for Settings A and C, and learned routing (P2) with missed attacks weighted more heavily.

1. Recall, false-positive rate, precision, F1 (confusion matrix = det / misses / FA / correct dismissals).
2. Analyst workload at the natural prevalence: Setting A evaluates every case, so its rates are natural; Setting C
   samples cases (malicious capped per network and type, benign stratified), so every case is weighted by
   population / sample size of its stratum. Reported per network and day.
3. P2 with objective  w * misses + false alarms + lambda * relative cost,  w in {1, 5, 10, 25}  (w = 1: paper).

Usage: .venv/bin/python scripts/operational.py  ->  results/operational.md
"""
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "v2"))
sys.argv = sys.argv[:1] + ["--all"]
import policies as P  # noqa: E402
import analyze_C as A  # noqa: E402

LAM = 0.05
WEIGHTS = [1, 5, 10, 25]


def metrics(decs, weight=None):
    """decs: (said_malicious, truth, cost, case); weight: case -> population weight (None = 1)."""
    w = (lambda c: 1.0) if weight is None else weight
    tp = sum(w(d[3]) for d in decs if d[0] and d[1])
    fn = sum(w(d[3]) for d in decs if not d[0] and d[1])
    fp = sum(w(d[3]) for d in decs if d[0] and not d[1])
    tn = sum(w(d[3]) for d in decs if not d[0] and not d[1])
    rec, fpr = tp / (tp + fn), fp / (fp + tn)
    prec = tp / (tp + fp) if tp + fp else 0.0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "rec": 100 * rec, "fpr": 100 * fpr, "prec": 100 * prec,
            "f1": 100 * 2 * prec * rec / (prec + rec) if prec + rec else 0.0, "ba": 50 * (rec + 1 - fpr),
            "cost": sum(d[2] for d in decs) / len(decs)}


def avg(ms):
    return {k: float(np.mean([m[k] for m in ms])) for k in ms[0]}


# ---------------------------------------------------------------- Setting A
def days_A():
    ts = [datetime.fromisoformat(P.CASES[c]["start"]) for c in P.KEEP]
    return {h: len({t.date() for t, c in zip(ts, P.KEEP) if P.CASES[c]["host"] == h}) for h in {P.CASES[c]["host"] for c in P.KEEP}}


def route_A(model, run, w):
    out = []
    for test in sorted({P.CASES[c]["host"] for c in run}):
        train = [c for c in run if P.CASES[c]["host"] != test]
        base = sum(P.cost(model, run[c]["L0_none"]) for c in train) / len(train)
        by = defaultdict(list)
        for c in train:
            by[P.CASES[c]["signature"]].append(c)

        def obj(cs, k):
            return sum((w if run[c][k]["truth"] else 1) * (P.said_mal(run[c][k]) != run[c][k]["truth"])
                       + LAM * P.cost(model, run[c][k]) / base for c in cs)
        choice = {s: min(P.CONDS, key=lambda k: obj(cs, k)) for s, cs in by.items()}
        for c in run:
            if P.CASES[c]["host"] == test:
                r = run[c][choice.get(P.CASES[c]["signature"], "only_ip")]
                out.append((P.said_mal(r), r["truth"], P.cost(model, r), c))
    return out


def setting_A():
    d = days_A()
    hostdays = sum(d.values())
    L = [f"## Setting A (589 cases, natural prevalence 25/589 = {100 * 25 / 589:.1f}%; {hostdays} server-days)", "",
         "| model | configuration | TP | FN | FP | TN | recall | FPR | precision | F1 | BA | escalations per server-day | false per server-day | $ per 1k |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    W = []
    for model in P.PRICE:
        runs = P.runs_of(model)
        for k in ["L0_none", "only_ip", "L4_+audit"]:
            m = avg([metrics([(P.said_mal(r[c][k]), r[c][k]["truth"], P.cost(model, r[c][k]), c) for c in r]) for r in runs])
            L.append(row(P.NAME[model], k, m, hostdays))
        for w in WEIGHTS:
            m = avg([metrics(route_A(model, r, w)) for r in runs])
            if w == 1:
                L.append(row(P.NAME[model], "P2 (w=1)", m, hostdays))
            W.append(row(P.NAME[model], f"P2 w={w}", m, hostdays))
    return L, W, hostdays


# ---------------------------------------------------------------- Setting C
IDS = set(A.SAMPLE)  # the 2,235 evaluated alerts


def weights_C():
    """Inverse sampling probability per stratum: malicious (network, type); benign (network, ambiguous type or not)."""
    pop = [c for c in A.CASES if A.CASES[c]["certain"] and c not in A.DROPPED]
    mal_desc = {A.CASES[c]["desc"] for c in pop if A.CASES[c]["truth"]}

    def stratum(c):
        x = A.CASES[c]
        return ("m", x["scenario"], x["desc"]) if x["truth"] else ("b", x["scenario"], x["desc"] in mal_desc)
    N, n = Counter(map(stratum, pop)), Counter(map(stratum, IDS))
    days = defaultdict(set)
    for c in pop:
        days[A.CASES[c]["scenario"]].add(int(float(A.CASES[c]["start"]) // 86400))
    return (lambda c: N[stratum(c)] / n[stratum(c)]), sum(len(v) for v in days.values()), \
        sum(A.CASES[c]["truth"] for c in pop), len(pop)


def route_C(model, run, conds, w):
    out = []
    for test in A.SCENS:
        train = [c for c in run if A.CASES[c]["scenario"] != test]
        base = sum(A.cost(model, run[c]["L0_none"]) for c in train) / len(train)
        by = defaultdict(list)
        for c in train:
            by[A.CASES[c]["desc"]].append(c)

        def obj(cs, k):
            return sum((w if run[c][k]["truth"] else 1) * (A.said(run[c][k]) != run[c][k]["truth"])
                       + LAM * A.cost(model, run[c][k]) / base for c in cs)
        choice = {s: min(conds, key=lambda k: obj(cs, k)) for s, cs in by.items()}
        for c in run:
            if A.CASES[c]["scenario"] == test:
                r = run[c][choice.get(A.CASES[c]["desc"], "only_ip")]
                out.append((A.said(r), r["truth"], A.cost(model, r), c))
    return out


def setting_C():
    wt, netdays, nmal, npop = weights_C()
    L = [f"## Setting C (sample 235/2235; natural prevalence {nmal}/{npop} = {100 * nmal / npop:.2f}%; {netdays} network-days)", "",
         "Sample metrics as evaluated; 'natural' columns reweight each case to the full population.", "",
         "| model | configuration | TP | FN | FP | TN | recall | FPR | precision (sample) | F1 (sample) | BA | precision (natural) | F1 (natural) | escalations per network-day | false per network-day | $ per 1k |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    W = []
    for model in A.PRICE:
        rs = A.runs(model, IDS)
        conds = [k for k in A.CONDITIONS if all(k in rs[0][c] for c in rs[0])]
        configs = [(k, lambda r, k=k: [(A.said(r[c][k]), r[c][k]["truth"], A.cost(model, r[c][k]), c) for c in r])
                   for k in ["L0_none", "only_ip", "L4_+host"]]
        for k, f in configs:
            L.append(rowC(A.NAME[model], k, [f(r) for r in rs], wt, netdays))
        for w in WEIGHTS:
            decs = [route_C(model, r, conds, w) for r in rs]
            if w == 1:
                L.append(rowC(A.NAME[model], "P2 (w=1)", decs, wt, netdays))
            W.append(rowC(A.NAME[model], f"P2 w={w}", decs, wt, netdays))
    return L, W


def row(name, k, m, hostdays):
    return (f"| {name} | {k} | {m['tp']:.1f} | {m['fn']:.1f} | {m['fp']:.1f} | {m['tn']:.1f} | {m['rec']:.1f} | {m['fpr']:.2f} | "
            f"{m['prec']:.1f} | {m['f1']:.1f} | {m['ba']:.1f} | {(m['tp'] + m['fp']) / hostdays:.2f} | {m['fp'] / hostdays:.2f} | {m['cost']:.2f} |")


def rowC(name, k, decs, wt, netdays):
    s = avg([metrics(d) for d in decs])
    n = avg([metrics(d, wt) for d in decs])
    return (f"| {name} | {k} | {s['tp']:.1f} | {s['fn']:.1f} | {s['fp']:.1f} | {s['tn']:.1f} | {s['rec']:.1f} | {s['fpr']:.2f} | "
            f"{s['prec']:.1f} | {s['f1']:.1f} | {s['ba']:.1f} | {n['prec']:.1f} | {n['f1']:.1f} | "
            f"{(n['tp'] + n['fp']) / netdays:.1f} | {n['fp'] / netdays:.1f} | {s['cost']:.2f} |")


def main():
    LA, WA, _ = setting_A()
    LC, WC = setting_C()
    hdrA, hdrC = LA[2:4], LC[4:6]
    L = ["# Operational metrics and cost-sensitive routing", ""] + LA + [""] + LC + [
        "", f"## P2 with missed attacks weighted w times a false alarm (lambda={LAM})", "", "### Setting A", ""] + hdrA + WA + \
        ["", "### Setting C", ""] + hdrC + WC
    open(os.path.join(P.BASE, "results", "operational.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
