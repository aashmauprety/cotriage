"""Setting C (AIT-LDS v2, 8 scenarios): tool ladder, per-scenario results, learned routing and
non-LLM baselines, all evaluated leave-one-scenario-out (train on 7 networks, test on the 8th).

Usage: .venv/bin/python scripts/v2/analyze_C.py  ->  results/settingC.md
"""
import bisect
import glob
import json
import math
import os
import sys
from collections import defaultdict

import numpy as np
from sklearn.ensemble import RandomForestClassifier

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tools_v2  # noqa: E402
from triage_v2 import CONDITIONS, load_cases  # noqa: E402

BASE = os.path.join(HERE, "..", "..")
# Gemini 3.7 Flash: introductory Vertex AI price until 2026-12-31 (1.5/7.5 USD per million tokens after)
PRICE = {"claude-haiku-5-5": (0.1e-6, 0.5e-6), "claude-opus-5-5": (4e-6, 20e-6), "gemini-3.7-flash": (0.75e-6, 3.75e-6),
         # Gemini 3.5 Flash-Lite: 0.30/2.50 per MTok (third-party trackers, Nov 2026; check Google page)
         "gemini-3.5-flash-lite": (0.30e-6, 2.50e-6)}
NAME = {"claude-haiku-5-5": "Haiku 5.5", "claude-opus-5-5": "Opus 5.5", "gemini-3.7-flash": "Gemini 3.7 Flash",
        "gemini-3.5-flash-lite": "Gemini 3.5 Flash-Lite"}
EXPENSIVE = {"ip_activity", "host_activity"}
CASES = load_cases()
# cases involving only the shared VPN gateway address during an attack phase are uncertain and excluded
# sample_C_dropped.txt: cases drawn as malicious that lost the label when DNS names that normal users also
# query (e.g. the company's own mail server, hit once by the attacker's DNS scan) were restricted to the scan
_dropped = os.path.join(BASE, "alerts_v2", "sample_C_dropped.txt")
DROPPED = {l.strip() for l in open(_dropped)} if os.path.exists(_dropped) else set()
SAMPLE = [c for c in (l.strip() for l in open(os.path.join(BASE, "alerts_v2", "sample_C.txt")))
          if c and CASES[c]["certain"] and c not in DROPPED]
_b2 = os.path.join(BASE, "alerts_v2", "sample_C_benign2.txt")
BENIGN2 = [l.strip() for l in open(_b2) if l.strip()] if os.path.exists(_b2) else []
SCENS = sorted({CASES[c]["scenario"] for c in SAMPLE})


def said(r):
    return (r["verdict"] or "malicious") == "malicious"


def cost(model, r):
    p = PRICE[model]
    return (r["prompt_tokens"] * p[0] + r["output_tokens"] * p[1]) * 1000


def runs(model, ids):
    """List of runs: case_id -> condition -> record (only runs that cover every id)."""
    out = []
    for p in sorted(glob.glob(os.path.join(BASE, "outputs", f"triageC_{model}*.jsonl"))):
        if "run99" in p:
            continue
        run = defaultdict(dict)
        for r in map(json.loads, open(p)):
            if r["case_id"] in ids:
                run[r["case_id"]][r["condition"]] = r
        run = defaultdict(dict, {c: v for c, v in run.items() if c in ids})
        if ids <= set(run):
            out.append(run)
    return out


def score(decs):
    """decs: (said_malicious, truth, cost, expensive_used)."""
    att = [d for d in decs if d[1]]
    ben = [d for d in decs if not d[1]]
    tp, fp = sum(d[0] for d in att), sum(d[0] for d in ben)
    return {"det": tp, "n_att": len(att), "fa": fp, "n_ben": len(ben),
            "ba": 50 * (tp / max(len(att), 1) + 1 - fp / max(len(ben), 1)),
            "cost": sum(d[2] for d in decs) / max(len(decs), 1),
            "exp": 100 * sum(d[3] for d in decs) / max(len(decs), 1)}


def mean(ss):
    return {k: sum(s[k] for s in ss) / len(ss) for k in ss[0]}


def fixed(model, run, cond):
    t = CONDITIONS[cond]
    return [(said(run[c][cond]), run[c][cond]["truth"], cost(model, run[c][cond]), bool(EXPENSIVE & set(t))) for c in run]


def routing(model, run, lam, conds):
    """P2: per alert type (description) the condition minimising errors + lam * cost / no-tool cost,
    learned on the other seven scenarios; unseen types get the best single tool."""
    out = []
    for test in SCENS:
        train = [c for c in run if CASES[c]["scenario"] != test]
        base = sum(cost(model, run[c]["L0_none"]) for c in train) / len(train)
        by = defaultdict(list)
        for c in train:
            by[CASES[c]["desc"]].append(c)
        choice = {d: min(conds, key=lambda k: sum((said(run[c][k]) != run[c][k]["truth"]) + lam * cost(model, run[c][k]) / base
                                                 for c in cs)) for d, cs in by.items()}
        for c in run:
            if CASES[c]["scenario"] == test:
                k = choice.get(CASES[c]["desc"], "only_ip")
                r = run[c][k]
                out.append((said(r), r["truth"], cost(model, r), bool(EXPENSIVE & set(CONDITIONS[k])), c))
    return out


# ---------------------------------------------------------------- non-LLM baselines
def features(ids):
    F = {}
    for c in ids:
        case = CASES[c]
        idx = tools_v2.index(case["scenario"])
        ts = idx["_t"]["alerts"]
        t0, t1 = case["start"], case["end"]
        recent = idx["alerts"][bisect.bisect_left(ts, t0 - 1800):bisect.bisect_left(ts, t0)]
        src = case["src"]
        other = [a for a in recent if src and src in (a[5], a[6])]
        day0 = t1 - t1 % 86400
        hist = idx["alerts"][:bisect.bisect_left(ts, day0)]
        days = max(tools_v2.prev_days(idx, t1), 1)
        host = tools_v2.norm_host(idx, case["host"])
        sig_rate = sum(1 for a in hist if a[4] == case["desc"] and tools_v2.norm_host(idx, a[1]) == host) / days
        pair_rate = sum(1 for a in hist if a[4] == case["desc"] and src and a[5] == src) / days
        F[c] = {"n": case["n_alerts"], "level": case["level"], "other": len(other),
                "other_sigs": len({a[4] for a in other}), "sig_rate": sig_rate, "pair_rate": pair_rate,
                "hour": int(t1 % 86400 // 3600), "burst": (case["n_alerts"] + len(other)) / (1 + pair_rate)}
    return F


def baselines(ids):
    F = features(ids)
    descs = sorted({CASES[c]["desc"] for c in ids})

    def X(cs):
        return np.array([[math.log1p(F[c]["n"]), F[c]["level"], math.log1p(F[c]["other"]), F[c]["other_sigs"],
                          math.log1p(F[c]["sig_rate"]), math.log1p(F[c]["pair_rate"]), F[c]["hour"], math.log1p(F[c]["burst"])]
                         + [float(CASES[c]["desc"] == d) for d in descs] for c in cs])

    def ba(pairs):
        return score([(p, t, 0, False) for p, t in pairs])["ba"]

    res = {}
    for name in ["Wazuh level", "Rarity / burst", "Random forest"]:
        decs = []
        for test in SCENS:
            tr = [c for c in ids if CASES[c]["scenario"] != test]
            te = [c for c in ids if CASES[c]["scenario"] == test]
            if name == "Wazuh level":
                L = max(range(3, 13), key=lambda l: ba([(F[c]["level"] >= l, CASES[c]["truth"]) for c in tr]))
                pred = [F[c]["level"] >= L for c in te]
            elif name == "Rarity / burst":
                T = max([1, 2, 5, 10, 20, 50], key=lambda t: ba([(F[c]["burst"] > t, CASES[c]["truth"]) for c in tr]))
                pred = [F[c]["burst"] > T for c in te]
            else:
                clf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
                clf.fit(X(tr), [CASES[c]["truth"] for c in tr])
                pred = list(clf.predict(X(te)).astype(bool))
            decs += [(p, CASES[c]["truth"], 0.0, False, c) for p, c in zip(pred, te)]
        res[name] = decs
    return res


def per_scen(decs):
    return [score([d for d in decs if CASES[d[-1]]["scenario"] == s])["ba"] for s in SCENS]


def main():
    ids = set(SAMPLE)
    L = ["# Setting C: AIT-LDS v2, 8 scenarios (leave-one-scenario-out for learned methods)", ""]
    n_att = sum(CASES[c]["truth"] for c in ids)
    L += [f"Sample: {len(ids)} cases ({n_att} malicious, {len(ids) - n_att} benign).", "",
          "| model | condition | runs | det | FA | BA | $ per 1k | " + " | ".join(SCENS) + " |",
          "|---|---|---|---|---|---|---|" + "---|" * len(SCENS)]
    allruns = {m: runs(m, ids) for m in PRICE}
    for m, rs in allruns.items():
        if not rs:
            continue
        conds = [k for k in CONDITIONS if all(k in rs[0][c] for c in rs[0])]
        for k in conds:
            sc = mean([score(fixed(m, r, k)) for r in rs])
            ps = np.mean([per_scen([d + (c,) for d, c in zip(fixed(m, r, k), r)]) for r in rs], axis=0)
            L.append(f"| {NAME[m]} | {k} | {len(rs)} | {sc['det']:.1f}/{sc['n_att']} | {sc['fa']:.1f}/{sc['n_ben']} | "
                     f"{sc['ba']:.1f} | {sc['cost']:.2f} | " + " | ".join(f"{x:.1f}" for x in ps) + " |")
        for lam in [0.0, 0.01, 0.05, 0.1]:
            decs = [routing(m, r, lam, conds) for r in rs]
            sc = mean([score([d[:4] for d in ds]) for ds in decs])
            ps = np.mean([per_scen(ds) for ds in decs], axis=0)
            L.append(f"| {NAME[m]} | P2 routing (lambda={lam}) | {len(rs)} | {sc['det']:.1f}/{sc['n_att']} | {sc['fa']:.1f}/{sc['n_ben']} | "
                     f"{sc['ba']:.1f} | {sc['cost']:.2f} | " + " | ".join(f"{x:.1f}" for x in ps) + f" | exp {sc['exp']:.0f}%")
    for name, decs in baselines(sorted(ids)).items():
        sc = score([d[:4] for d in decs])
        L.append(f"| no LLM | {name} | - | {sc['det']}/{sc['n_att']} | {sc['fa']}/{sc['n_ben']} | {sc['ba']:.1f} | 0 | "
                 + " | ".join(f"{x:.1f}" for x in per_scen(decs)) + " |")
    # sensitivity: false-alarm rate of Haiku run 1 on the second, disjoint benign sample
    b2 = runs("claude-haiku-5-5", set(BENIGN2))
    if b2:
        L += ["", "## Sensitivity: second benign sample (Haiku, run 1)", "",
              "| condition | FA sample 1 (%) | FA sample 2 (%) |", "|---|---|---|"]
        r1 = allruns["claude-haiku-5-5"][0]
        for k in CONDITIONS:
            f1 = score(fixed("claude-haiku-5-5", r1, k))
            f2 = score(fixed("claude-haiku-5-5", b2[0], k))
            L.append(f"| {k} | {100 * f1['fa'] / f1['n_ben']:.2f} | {100 * f2['fa'] / f2['n_ben']:.2f} |")
    open(os.path.join(BASE, "results", "settingC.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
