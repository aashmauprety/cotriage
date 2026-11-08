"""Learned stopping along the tool ladder (instance-adaptive, cf. Feng et al. 2026) vs. signature routing (P2).

Per alert, the model is queried at L0; at every ladder level k the model's confidence c (about P(malicious))
decides whether to stop or to query the next level: continue iff l_k <= c <= h_k. The alert pays every level
queried (as P1). The bands are learned from offline outcomes on the training networks (leave-one-scenario-out
in Setting C, leave-one-host-out in Setting A) by coordinate descent over a 0.05 grid, minimising
errors + LAM * cumulative cost / mean no-tool cost (the P2 objective).

  P1 [0.2, 0.8]          fixed band at every level
  learned (shared)       one band per level
  learned (per verdict)  one band per level and verdict
  learned, free cost     shared band, but only the final level's cost is charged (optimistic bound)
  hybrid                 P2's tool set per signature; escalate to all tools if its confidence is in a learned band
  oracle stop            per alert the stopping level minimising the objective on the test alert (upper bound)

Usage: .venv/bin/python scripts/v2/learned_stopping_C.py  ->  results/learned_stopping_C.md
"""
import os
import sys
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.argv = sys.argv[:1] + ["--all"]
import policies as P  # noqa: E402
import analyze_C as A  # noqa: E402

LAM = 0.05
GRID = np.round(np.arange(0, 1.0001, 0.05), 2)
BANDS = [(1.0, 0.0)] + [(l, h) for l in GRID for h in GRID if l <= h]  # (1, 0) = never continue
IDS_C = set(A.SAMPLE)  # the 2,235 evaluated alerts


class Data:
    """Arrays over cases (n) and ladder levels (K) for one model and run, plus every condition for P2."""

    def __init__(self, run, ladder, conds, said, cost, fold, sig):
        self.ids = sorted(run)
        self.ladder, self.conds = ladder, conds
        get = lambda k, f: np.array([f(run[c][k]) for c in self.ids])
        self.truth = get(ladder[0], lambda r: bool(r["truth"]))
        self.said = {k: get(k, said) for k in conds}
        self.cost = {k: get(k, cost) for k in conds}
        self.conf = {k: get(k, lambda r: 0.5 if r["confidence"] is None else float(r["confidence"])) for k in conds}
        self.fold = np.array([fold(c) for c in self.ids])
        self.sig = np.array([sig(c) for c in self.ids])


def walk(D, idx, bands, free=False):
    """bands[k] = {verdict: (l, h)} for levels 0..K-2. Returns said, cost, level reached (index arrays)."""
    K = len(D.ladder)
    n = len(idx)
    active = np.ones(n, bool)
    said, total, last, level = np.zeros(n, bool), np.zeros(n), np.zeros(n), np.zeros(n, int)
    for k, cond in enumerate(D.ladder):
        s, c, f = D.said[cond][idx], D.conf[cond][idx], D.cost[cond][idx]
        total = total + active * f
        last = np.where(active, f, last)
        said = np.where(active, s, said)
        level = np.where(active, k, level)
        if k == K - 1:
            break
        l = np.where(s, bands[k][True][0], bands[k][False][0])
        h = np.where(s, bands[k][True][1], bands[k][False][1])
        active = active & (l <= c) & (c <= h)
    return said, (last if free else total), level


def objective(D, idx, said, cost, base):
    return np.sum(said != D.truth[idx]) + LAM * np.sum(cost) / base


def fit(D, idx, base, per_verdict, free=False):
    K = len(D.ladder)
    keys = [(k, v) for k in range(K - 1) for v in ((True, False) if per_verdict else (None,))]
    best = None
    for init in [(1.0, 0.0), (0.0, 1.0)]:  # start from "always stop" and from "always continue"
        bands = [{True: init, False: init} for _ in range(K - 1)]
        J = objective(D, idx, *walk(D, idx, bands, free)[:2], base)
        for _ in range(6):
            changed = False
            for k, v in keys:
                for b in BANDS:
                    trial = [dict(x) for x in bands]
                    if v is None:
                        trial[k] = {True: b, False: b}
                    else:
                        trial[k][v] = b
                    j = objective(D, idx, *walk(D, idx, trial, free)[:2], base)
                    if j < J - 1e-12:
                        J, bands, changed = j, trial, True
            if not changed:
                break
        if best is None or J < best[0]:
            best = (J, bands)
    return best[1]


def p2_choice(D, idx, base):
    by = defaultdict(list)
    for i in idx:
        by[D.sig[i]].append(i)
    return {s: min(D.conds, key=lambda k: np.sum(D.said[k][ii] != D.truth[ii]) + LAM * np.sum(D.cost[k][ii]) / base)
            for s, ii in by.items()}


def hybrid(D, idx, choice, fallback, band):
    top = D.ladder[-1]
    k0 = [choice.get(D.sig[i], fallback) for i in idx]
    s0 = np.array([D.said[k][i] for k, i in zip(k0, idx)])
    c0 = np.array([D.cost[k][i] for k, i in zip(k0, idx)])
    p0 = np.array([D.conf[k][i] for k, i in zip(k0, idx)])
    esc = (band[0] <= p0) & (p0 <= band[1]) & np.array([k != top for k in k0])
    return np.where(esc, D.said[top][idx], s0), c0 + esc * D.cost[top][idx], esc


def evaluate(D, fallback):
    """Decisions of every policy for one run: name -> (said, truth, cost, level, reached_last) over all cases."""
    out = defaultdict(lambda: [[], [], [], [], []])
    K = len(D.ladder)

    def add(name, idx, said, cost, level):
        o = out[name]
        o[0] += list(said); o[1] += list(D.truth[idx]); o[2] += list(cost); o[3] += list(level + 1)
        o[4] += list(level == K - 1)
    for test in sorted(set(D.fold)):
        tr, te = np.where(D.fold != test)[0], np.where(D.fold == test)[0]
        base = np.mean(D.cost[D.ladder[0]][tr])
        p1 = [{True: (0.2, 0.8), False: (0.2, 0.8)}] * (K - 1)
        add("P1 [0.2, 0.8]", te, *walk(D, te, p1))
        for name, pv, free in [("learned stopping (shared band)", False, False),
                               ("learned stopping (per-verdict band)", True, False),
                               ("learned stopping, free earlier calls", False, True)]:
            add(name, te, *walk(D, te, fit(D, tr, base, pv, free), free))
        # oracle: per test alert the best stopping level
        cum = np.cumsum([D.cost[k][te] for k in D.ladder], axis=0)
        errs = np.array([D.said[k][te] != D.truth[te] for k in D.ladder])
        best = np.argmin(errs + LAM * cum / base, axis=0)
        add("oracle stop per alert", te, np.array([D.said[D.ladder[b]][i] for b, i in zip(best, te)]),
            cum[best, np.arange(len(te))], best)
        # P2 and hybrid
        choice = p2_choice(D, tr, base)
        k2 = [choice.get(D.sig[i], fallback) for i in te]
        add(f"P2 signature routing (lambda={LAM})", te, np.array([D.said[k][i] for k, i in zip(k2, te)]),
            np.array([D.cost[k][i] for k, i in zip(k2, te)]), np.array([K - 1 if k == D.ladder[-1] else 0 for k in k2]))
        Jb, bb = None, None
        for b in BANDS:
            s, c, _ = hybrid(D, tr, choice, fallback, b)  # in-sample P2 choices on the training alerts
            j = objective(D, tr, s, c, base)
            if Jb is None or j < Jb - 1e-12:
                Jb, bb = j, b
        s, c, esc = hybrid(D, te, choice, fallback, bb)
        add("hybrid: P2 + escalate to all tools on learned band", te, s, c, np.where(esc, K - 1, 0))
    return out


def score(o):
    said, truth, cost, lev, last = (np.array(x) for x in o)
    tp, fp = np.sum(said & truth), np.sum(said & ~truth)
    return {"det": tp, "fa": fp, "ba": 50 * (tp / truth.sum() + 1 - fp / (~truth).sum()), "cost": cost.mean(),
            "lev": lev.mean(), "last": 100 * last.mean()}


def table(name, models):
    L = [f"## Setting {name}", "",
         "| model | policy | det | FA | BA | $ per 1k | mean ladder levels queried | % reaching last level |",
         "|---|---|---|---|---|---|---|---|"]
    for nm, runs, ladder, mk in models:
        fixed = defaultdict(list)
        res = defaultdict(list)
        for run in runs:
            D = mk(run)
            for k in (ladder[0], ladder[-1]):
                fixed[k].append(score([list(D.said[k]), list(D.truth), list(D.cost[k]), [0] * len(D.ids), [0] * len(D.ids)]))
            for pol, o in evaluate(D, D.fallback).items():
                res[pol].append(score(o))
        rows = [(f"fixed {k}", v) for k, v in fixed.items()] + list(res.items())
        for pol, sc in rows:
            m = {k: np.mean([s[k] for s in sc]) for k in sc[0]}
            lv = "-" if pol.startswith("fixed") else f"{m['lev']:.2f}"
            la = "-" if pol.startswith("fixed") else f"{m['last']:.1f}"
            L.append(f"| {nm} ({len(runs)} runs) | {pol} | {m['det']:.1f} | {m['fa']:.1f} | {m['ba']:.1f} | {m['cost']:.2f} | {lv} | {la} |")
    return L + [""]


def setting_C():
    models = []
    for m in A.PRICE:
        rs = A.runs(m, IDS_C)
        conds = [k for k in A.CONDITIONS if all(k in rs[0][c] for c in rs[0])]
        ladder = [k for k in ["L0_none", "L1_history", "L2_+context", "L3_+ip", "L4_+host"] if k in conds]

        def mk(run, ladder=ladder, conds=conds, m=m):
            D = Data(run, ladder, conds, A.said, lambda r: A.cost(m, r), lambda c: A.CASES[c]["scenario"],
                     lambda c: A.CASES[c]["desc"])
            D.fallback = "only_ip"
            return D
        models.append((A.NAME[m], rs, ladder, mk))
    return table("C (2235 cases, leave-one-scenario-out)", models)


def setting_A():
    models = []
    for m in P.PRICE:
        rs = P.runs_of(m)

        def mk(run, m=m):
            D = Data(run, P.LADDER, P.CONDS, P.said_mal, lambda r: P.cost(m, r), lambda c: P.CASES[c]["host"],
                     lambda c: P.CASES[c]["signature"])
            D.fallback = "only_ip"
            return D
        models.append((P.NAME[m], rs, P.LADDER, mk))
    return table("A (589 cases, leave-one-host-out)", models)


def sensitivity_C():
    """Learned stopping (shared and per-verdict band) at smaller lambda, Setting C: is the cost term the reason?"""
    global LAM
    L = ["## Setting C: learned stopping at smaller lambda", "",
         "| lambda | model | band | det | FA | BA | $ per 1k | mean levels | % last level |", "|---|---|---|---|---|---|---|---|---|"]
    keep = LAM
    for lam in (0.0, 0.01):
        LAM = lam
        for m in A.PRICE:
            rs = A.runs(m, IDS_C)
            conds = [k for k in A.CONDITIONS if all(k in rs[0][c] for c in rs[0])]
            ladder = [k for k in ["L0_none", "L1_history", "L2_+context", "L3_+ip", "L4_+host"] if k in conds]
            res = defaultdict(list)
            for run in rs:
                D = Data(run, ladder, conds, A.said, lambda r: A.cost(m, r), lambda c: A.CASES[c]["scenario"],
                         lambda c: A.CASES[c]["desc"])
                out = defaultdict(lambda: [[], [], [], [], []])
                for test in sorted(set(D.fold)):
                    tr, te = np.where(D.fold != test)[0], np.where(D.fold == test)[0]
                    base = np.mean(D.cost[ladder[0]][tr])
                    for pv in (False, True):
                        s, c, l = walk(D, te, fit(D, tr, base, pv))
                        o = out[pv]
                        o[0] += list(s); o[1] += list(D.truth[te]); o[2] += list(c); o[3] += list(l + 1)
                        o[4] += list(l == len(ladder) - 1)
                for pv, o in out.items():
                    res[pv].append(score(o))
            for pv, sc in res.items():
                x = {k: np.mean([v[k] for v in sc]) for k in sc[0]}
                L.append(f"| {lam} | {A.NAME[m]} | {'per verdict' if pv else 'shared'} | {x['det']:.1f} | {x['fa']:.1f} | "
                         f"{x['ba']:.1f} | {x['cost']:.2f} | {x['lev']:.2f} | {x['last']:.1f} |")
    LAM = keep
    return L + [""]


def main():
    L = ["# Learned stopping along the tool ladder vs. signature routing", "",
         f"lambda={LAM}; cost = every ladder level queried (except 'free earlier calls'); mean over runs.",
         "Levels: Setting C Haiku/Gemini L0..L4 (5), Opus L0, L1, L4 (3); Setting A L0..L4 (5).",
         "P2 'levels' column: 1 = not all tools, K = all tools. Hybrid: P2 choices on training alerts are in-sample.", ""]
    L += setting_C() + sensitivity_C() + setting_A()
    out = os.path.join(A.BASE, "results", "learned_stopping_C.md")
    open(out, "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
