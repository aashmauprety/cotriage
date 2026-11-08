"""Paired bootstrap of the balanced-accuracy difference between learned routing (P2) and the two alternatives of
Fig. 2 at lambda=0.05, Setting C: global routing (one tool set for all alerts, same objective) and learned stopping
(one band per ladder level and verdict). As in bootstrap_ci.py: a case's decision is the mean over runs, cases are
resampled within class, all methods on the same resamples; learned methods trained once per fold.

Usage: .venv/bin/python scripts/bootstrap_routing.py  ->  results/bootstrap_routing.md
"""
import os
import sys
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "v2"))
import bootstrap_ci as B  # noqa: E402
from routing_baselines import Setting, P  # noqa: E402
import learned_stopping_C as LS  # noqa: E402

LAM = 0.05
MODELS = ["claude-haiku-5-5", "gemini-3.5-flash-lite", "gemini-3.7-flash", "claude-opus-5-5"]


def routing(S, m, r, conds):
    """{case: said} for P2 and global routing, leave-one-scenario-out."""
    p2, gl = {}, {}
    for t in sorted({S.fold(c) for c in r}):
        tr = [c for c in r if S.fold(c) != t]
        base = sum(S.cost(m, r[c]["L0_none"]) for c in tr) / len(tr)
        J = lambda cs, k: sum((S.said(r[c][k]) != r[c][k]["truth"]) + LAM * S.cost(m, r[c][k]) / base for c in cs)
        by = defaultdict(list)
        for c in tr:
            by[S.sig(c)].append(c)
        ch = {s: min(conds, key=lambda k: J(cs, k)) for s, cs in by.items()}
        g = min(conds, key=lambda k: J(tr, k))
        for c in r:
            if S.fold(c) == t:
                p2[c] = bool(S.said(r[c][ch.get(S.sig(c), "only_ip")]))
                gl[c] = bool(S.said(r[c][g]))
    return p2, gl


def stopping(m, r, conds):
    A = LS.A
    LS.LAM = LAM
    ladder = [k for k in ["L0_none", "L1_history", "L2_+context", "L3_+ip", "L4_+host"] if k in conds]
    D = LS.Data(r, ladder, conds, A.said, lambda x: A.cost(m, x), lambda c: A.CASES[c]["scenario"], lambda c: A.CASES[c]["desc"])
    out = {}
    for t in sorted(set(D.fold)):
        tr, te = np.where(D.fold != t)[0], np.where(D.fold == t)[0]
        s, _, _ = LS.walk(D, te, LS.fit(D, tr, np.mean(D.cost[ladder[0]][tr]), True))
        out.update({D.ids[i]: bool(v) for i, v in zip(te, s)})
    return out


def main():
    S = Setting("C")
    L = ["# Paired bootstrap: routing vs. global routing and learned stopping (Setting C, lambda=0.05)", ""]
    for m in MODELS:
        rs = S.runs(m)
        conds = S.conds(m, rs[0])
        per = [routing(S, m, r, conds) for r in rs]
        meth = {"P2 routing": B.mean_pred([p for p, _ in per]), "global routing": B.mean_pred([g for _, g in per]),
                "learned stopping": B.mean_pred([stopping(m, r, conds) for r in rs])}
        truth = {c: bool(rs[0][c]["L0_none"]["truth"]) for c in rs[0]}
        L += B.report(S.nm[m], meth, truth, [("P2 routing", "global routing"), ("P2 routing", "learned stopping")])
    out = os.path.join(P.BASE, "results", "bootstrap_routing.md")
    open(out, "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
