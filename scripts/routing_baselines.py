"""Simple baselines for learned routing (P2) and stability of its choices, Settings A and C.

  per-signature, no cost (lambda=0)   best tool set per signature by training errors only
  P2 (lambda=0.05)                    the paper's policy
  global, same objective              one tool set for every alert, chosen by Eq. (5) on the training folds
  global, same budget                 one tool set for every alert: fewest training errors among sets whose
                                      training cost is at most the training cost of P2
Stability: for each signature, the number of distinct tool sets chosen over folds (and runs).

Usage: .venv/bin/python scripts/routing_baselines.py  ->  results/routing_baselines.md
"""
import os
import sys
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "v2"))
sys.argv = sys.argv[:1] + ["--all"]
import policies as P  # noqa: E402
import analyze_C as A  # noqa: E402

LAM = 0.05
IDS_C = set(l.strip() for l in open(os.path.join(A.BASE, "alerts_v2", "sample_C_gemini.txt")) if l.strip())


class Setting:
    def __init__(self, name):
        self.name = name
        if name == "A":
            self.models, self.fold = list(P.PRICE), lambda c: P.CASES[c]["host"]
            self.sig = lambda c: P.CASES[c]["signature"]
            self.said, self.cost, self.nm = P.said_mal, P.cost, P.NAME
            self.runs = lambda m: P.runs_of(m)
            self.conds = lambda m, r: P.CONDS
        else:
            self.models, self.fold = list(A.PRICE), lambda c: A.CASES[c]["scenario"]
            self.sig = lambda c: A.CASES[c]["desc"]
            self.said, self.cost, self.nm = A.said, A.cost, A.NAME
            self.runs = lambda m: A.runs(m, IDS_C)
            self.conds = lambda m, r: [k for k in A.CONDITIONS if all(k in r[c] for c in r)]


def err(S, r, c, k):
    return S.said(r[c][k]) != r[c][k]["truth"]


def policies(S, m, r):
    """Decisions of every policy (said, truth, cost) and the per-fold choice of P2 per signature."""
    conds = S.conds(m, r)
    out = defaultdict(list)
    choices = defaultdict(set)
    for test in sorted({S.fold(c) for c in r}):
        train = [c for c in r if S.fold(c) != test]
        tst = [c for c in r if S.fold(c) == test]
        base = sum(S.cost(m, r[c]["L0_none"]) for c in train) / len(train)
        by = defaultdict(list)
        for c in train:
            by[S.sig(c)].append(c)

        def J(cs, k, lam):
            return sum(err(S, r, c, k) + lam * S.cost(m, r[c][k]) / base for c in cs)
        sig0 = {s: min(conds, key=lambda k: J(cs, k, 0.0)) for s, cs in by.items()}
        sig = {s: min(conds, key=lambda k: J(cs, k, LAM)) for s, cs in by.items()}
        for s, k in sig.items():
            choices[s].add(k)
        g_obj = min(conds, key=lambda k: J(train, k, LAM))
        p2_cost = sum(S.cost(m, r[c][sig[S.sig(c)]]) for c in train)
        within = [k for k in conds if sum(S.cost(m, r[c][k]) for c in train) <= p2_cost] or ["L0_none"]
        g_bud = min(within, key=lambda k: J(train, k, 0.0))
        for name, pick in [("per-signature, no cost (lambda=0)", lambda c: sig0.get(S.sig(c), "only_ip")),
                           (f"P2 (lambda={LAM})", lambda c: sig.get(S.sig(c), "only_ip")),
                           ("global, same objective", lambda c: g_obj),
                           ("global, same budget", lambda c: g_bud)]:
            for c in tst:
                k = pick(c)
                out[name].append((S.said(r[c][k]), r[c][k]["truth"], S.cost(m, r[c][k]), k))
    return out, choices


def score(decs):
    att = [d for d in decs if d[1]]
    ben = [d for d in decs if not d[1]]
    tp, fp = sum(d[0] for d in att), sum(d[0] for d in ben)
    return {"det": tp, "fa": fp, "ba": 50 * (tp / len(att) + 1 - fp / len(ben)), "cost": np.mean([d[2] for d in decs])}


def main():
    L = ["# Routing baselines and stability", ""]
    for name in ["A", "C"]:
        S = Setting(name)
        L += [f"## Setting {name}", "", "| model | policy | det | FA | BA | $ per 1k | tool sets used |", "|---|---|---|---|---|---|---|"]
        stab = []
        for m in S.models:
            rs = S.runs(m)
            if not rs:
                continue
            res = [policies(S, m, r) for r in rs]
            for pol in res[0][0]:
                sc = [score(o[pol]) for o, _ in res]
                used = sorted({d[3] for o, _ in res for d in o[pol]})
                L.append(f"| {S.nm[m]} | {pol} | {np.mean([s['det'] for s in sc]):.1f} | {np.mean([s['fa'] for s in sc]):.1f} | "
                         f"{np.mean([s['ba'] for s in sc]):.1f} | {np.mean([s['cost'] for s in sc]):.2f} | {', '.join(used) if len(used) <= 2 else len(used)} |")
            per_fold = [len(ch) for _, chs in res for ch in chs.values()]
            allch = defaultdict(set)
            for _, chs in res:
                for s, ks in chs.items():
                    allch[s] |= ks
            stab.append(f"| {S.nm[m]} | {len(allch)} | {np.mean([n == 1 for n in per_fold]) * 100:.0f}% | "
                        f"{np.mean([len(v) == 1 for v in allch.values()]) * 100:.0f}% |")
        L += ["", "Stability of P2: within one fold every alert of a signature gets the same tool set (by construction).", "",
              "| model | signatures | same set in every fold (per run) | same set in every fold and run |", "|---|---|---|---|"] + stab + [""]
    out = os.path.join(P.BASE, "results", "routing_baselines.md")
    open(out, "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
