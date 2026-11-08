"""95% bootstrap confidence intervals of the balanced accuracy (Settings A and C) and paired
differences between methods.

Cases are resampled with replacement within each class (attack / benign), so every resample has the
same class sizes. Methods are compared on the same resamples (paired bootstrap). For Haiku, a case's
decision is the mean over the three runs, as in the tables. Learned methods (P2, random forest) are
trained once per fold; the interval covers the variation of the test cases, not of the training.

Usage: .venv/bin/python scripts/bootstrap_ci.py  ->  results/bootstrap_ci.md
"""
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, "..")
sys.argv = [sys.argv[0], "--all"]  # policies.py: all 589 cases
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "v2"))
B_ITER = 5000
rng = np.random.default_rng(0)


def mean_pred(runs_of_decs):
    """runs_of_decs: list over runs of {case_id: bool} -> {case_id: mean prediction}."""
    ids = set.intersection(*(set(d) for d in runs_of_decs))
    return {c: float(np.mean([d[c] for d in runs_of_decs])) for c in ids}


def boot(methods, truth):
    """methods: name -> {case_id: prediction in [0, 1]}. Returns name -> array of BA over resamples."""
    ids = sorted(set.intersection(*(set(m) for m in methods.values())))
    att = np.array([c for c in ids if truth[c]])
    ben = np.array([c for c in ids if not truth[c]])
    ia = rng.integers(0, len(att), (B_ITER, len(att)))
    ib = rng.integers(0, len(ben), (B_ITER, len(ben)))
    out = {}
    for name, m in methods.items():
        pa = np.array([m[c] for c in att])
        pb = np.array([m[c] for c in ben])
        point = 50 * (pa.mean() + 1 - pb.mean())
        out[name] = (point, 50 * (pa[ia].mean(1) + 1 - pb[ib].mean(1)))
    return out, len(att), len(ben)


def ci(x):
    return np.percentile(x, 2.5), np.percentile(x, 97.5)


def report(title, methods, truth, pairs):
    res, na, nb = boot(methods, truth)
    L = [f"## {title} ({na} attacks, {nb} benign; {B_ITER} stratified resamples)", "",
         "| method | BA | 95% CI |", "|---|---|---|"]
    for name, (p, s) in res.items():
        lo, hi = ci(s)
        L.append(f"| {name} | {p:.1f} | {lo:.1f}-{hi:.1f} |")
    L += ["", "| comparison | difference (BA points) | 95% CI | share of resamples > 0 |", "|---|---|---|---|"]
    for a, b in pairs:
        d = res[a][1] - res[b][1]
        lo, hi = ci(d)
        L.append(f"| {a} minus {b} | {res[a][0] - res[b][0]:+.1f} | {lo:+.1f} to {hi:+.1f} | {100 * (d > 0).mean():.1f}% |")
    return L + [""]


def setting_a():
    import ablation_p2 as A
    import baselines as Bl
    import policies as P
    from sklearn.ensemble import RandomForestClassifier
    truth = {c: P.CASES[c]["truth"] for c in P.KEEP}
    H, O = P.runs_of("claude-haiku-5-5"), P.runs_of("claude-opus-5-5")
    fixed = lambda m, runs, cond: mean_pred([{c: P.said_mal(r[c][cond]) for c in r} for r in runs])
    pol = lambda m, runs: mean_pred([{d[5]: d[0] for d in A.policy(m, r, 0.05, "sig")} for r in runs])
    F = Bl.alarm_features()
    sigs = sorted({c["signature"] for c in Bl.CASES})
    rf = {}
    for h in Bl.HOSTS:
        tr = [c for c in Bl.CASES if c["host"] != h]
        te = [c for c in Bl.CASES if c["host"] == h]
        clf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
        clf.fit(Bl.matrix(tr, F, sigs), [c["truth"] for c in tr])
        rf.update({c["case_id"]: float(p) for c, p in zip(te, clf.predict(Bl.matrix(te, F, sigs)))})
    methods = {
        "Random forest": rf,
        "Haiku S0": fixed("h", H, "L0_none"), "Haiku tau3": fixed("h", H, "only_ip"),
        "Haiku S4": fixed("h", H, "L4_+audit"), "Haiku P2": pol("claude-haiku-5-5", H),
        "Opus S0": fixed("o", O, "L0_none"), "Opus tau3": fixed("o", O, "only_ip"), "Opus P2": pol("claude-opus-5-5", O),
    }
    pairs = [("Haiku tau3", "Opus S0"), ("Haiku S4", "Random forest"), ("Haiku S4", "Opus S0"),
             ("Haiku P2", "Haiku S0"), ("Opus P2", "Opus S0"), ("Haiku S4", "Haiku P2")]
    return report("Setting A, all 589 cases", methods, truth, pairs)


def setting_c():
    import analyze_C as C
    ids = set(C.SAMPLE)
    truth = {c: C.CASES[c]["truth"] for c in ids}
    out = {}
    for m, key in [("claude-haiku-5-5", "Haiku"), ("claude-opus-5-5", "Opus"), ("gemini-3.7-flash", "Gemini"), ("gemini-3.5-flash-lite", "Lite")]:
        rs = C.runs(m, ids)
        conds = [k for k in C.CONDITIONS if all(k in rs[0][c] for c in rs[0])]
        for k, label in [("L0_none", "S0"), ("L4_+host", "S4"), ("only_ip", "tau3")]:
            out[f"{key} {label}"] = mean_pred([{c: C.said(r[c][k]) for c in r} for r in rs])
        out[f"{key} P2"] = mean_pred([{d[4]: d[0] for d in C.routing(m, r, 0.05, conds)} for r in rs])
    for name, decs in C.baselines(sorted(ids)).items():
        out[name] = {d[4]: float(d[0]) for d in decs}
    pairs = [("Haiku P2", "Haiku S4"), ("Haiku P2", "Haiku S0"), ("Opus P2", "Opus S0"),
             ("Opus P2", "Random forest"), ("Opus S4", "Random forest"), ("Haiku S4", "Opus S0"),
             ("Random forest", "Haiku P2"), ("Gemini P2", "Gemini S0"), ("Gemini P2", "Gemini S4"),
             ("Gemini P2", "Random forest"), ("Gemini S4", "Opus S0"),
             ("Lite S4", "Lite S0"), ("Lite P2", "Lite S0"), ("Lite S4", "Opus S0"), ("Lite S4", "Haiku S4")]
    return report("Setting C, eight scenarios", out, truth, pairs)


if __name__ == "__main__":
    L = ["# Bootstrap confidence intervals of the balanced accuracy", ""] + setting_a() + setting_c()
    open(os.path.join(BASE, "results", "bootstrap_ci.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))
