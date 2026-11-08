"""Ablation of the learned cost-aware stopping policy (P2 in the paper, P5 in policies.py).

Same objective (errors + lambda * relative cost), same leave-one-host-out protocol, three
cell definitions:
  sig        cell = signature
  burst      cell = 1[burst ratio > T], T chosen on the training hosts
  sig+burst  cell = (signature, 1[burst ratio > T])   (the paper's P2)
Also reports, for each held-out host, every cell with its training support
(training alerts / malicious training alerts) and the selected tool configuration.
Computed from existing answers on all 589 cases (no LLM calls).

Usage: .venv/bin/python scripts/ablation_p2.py  ->  results/ablation_p2.md
"""
import os
import sys
from collections import Counter, defaultdict

sys.argv.append("--all")
import policies as P  # noqa: E402

MODES = ["sig", "burst", "sig+burst"]
LAMBDAS = [0.0, 0.01, 0.05, 0.1]
SHORT = {"L0_none": "S0", "L1_history": "S1", "L2_+suricata": "S2", "L3_+ip": "S3", "L4_+audit": "S4",
         "only_suricata": "t2", "only_ip": "t3", "only_audit": "t4"}


def cell(c, mode, T, feats):
    sig = P.CASES[c]["signature"].replace("ET POLICY Http Client Body contains pass= in cleartext", "cleartext pass=")
    z = feats[c] > T
    return {"sig": (sig,), "burst": (z,), "sig+burst": (sig, z)}[mode]


def policy(model, run, lam, mode, log=None):
    feats = P.features()
    out = []
    for test in sorted({P.CASES[c]["host"] for c in run}):
        train = [c for c in run if P.CASES[c]["host"] != test]
        base = sum(P.cost(model, run[c]["L0_none"]) for c in train) / len(train)

        def fit(T):
            cells = defaultdict(list)
            for c in train:
                cells[cell(c, mode, T, feats)].append(c)
            choice, loss = {}, 0.0
            for k, cs in cells.items():
                def obj(cond):
                    return sum((P.said_mal(run[c][cond]) != run[c][cond]["truth"])
                               + lam * P.cost(model, run[c][cond]) / base for c in cs)
                choice[k] = min(P.CONDS, key=obj)
                loss += obj(choice[k])
            return loss, choice, cells

        thresholds = [0] if mode == "sig" else P.THRESHOLDS
        T, (_, choice, cells) = min(((T, fit(T)) for T in thresholds), key=lambda x: x[1][0])
        if log is not None:
            for k in sorted(cells, key=str):
                cs = cells[k]
                log.append((test.split(".")[1], T if mode != "sig" else "-", " / ".join(map(str, k)),
                            len(cs), sum(P.CASES[c]["truth"] for c in cs), SHORT[choice[k]]))
        for c in run:
            if P.CASES[c]["host"] != test:
                continue
            k = cell(c, mode, T, feats)
            if k not in choice and mode == "sig+burst":  # unseen burst side: other side of the signature
                k = (k[0], not k[1])
            cond = choice.get(k, "only_ip")
            r = run[c][cond]
            out.append((P.said_mal(r), r["truth"], P.cost(model, r), len(P.COND_TOOLS[cond]),
                        bool(P.EXPENSIVE & set(P.COND_TOOLS[cond])), c))
    return out


def main():
    lines = ["# Ablation of the learned stopping policy (Setting A, all 589 cases, leave-one-host-out)", "",
             "| model | cells | lambda | det /25 | FA /564 | BA | $ per 1k | expensive tools (%) | BA cup | BA insect | BA onion | BA spiral |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    hosts = sorted({P.CASES[c]["host"] for c in P.KEEP})
    support = {}
    for model in P.PRICE:
        runs = P.runs_of(model)
        for mode in MODES:
            for lam in LAMBDAS:
                decs = [policy(model, run, lam, mode) for run in runs]
                m = P.mean([P.score(d) for d in decs])
                per = []
                for h in hosts:
                    hs = [P.score([d for d in ds if P.CASES[d[5]]["host"] == h]) for ds in decs]
                    per.append(f"{sum(s['ba'] for s in hs) / len(hs):.1f}")
                lines.append(f"| {P.NAME[model]} | {mode} | {lam} | {m['det']:.1f} | {m['fa']:.1f} | {m['ba']:.1f} | "
                             f"{m['cost']:.2f} | {m['expensive']:.0f} | " + " | ".join(per) + " |")
        for mode, lam in [("sig", 0.01), ("burst", 0.01), ("sig+burst", 0.01), ("sig+burst", 0.05)]:
            # selected configuration per cell and fold; for Haiku, how often each choice occurs over the 3 runs
            per_run = []
            for run in runs:
                log = []
                policy(model, run, lam, mode, log)
                per_run.append(log)
            agg = defaultdict(Counter)
            info, Ts = {}, defaultdict(set)
            for log in per_run:
                for host, T, k, n, nm, ch in log:
                    agg[(host, k)][ch] += 1
                    Ts[(host, k)].add(str(T))
                    info[(host, k)] = (n, nm)
            support[(model, mode, lam)] = [(h, k, ",".join(sorted(Ts[(h, k)], key=lambda t: (len(t), t))), *info[(h, k)], ", ".join(f"{c}x{n}" if len(runs) > 1 else c
                                                                       for c, n in agg[(h, k)].most_common()))
                                           for (h, k) in sorted(agg)]
    lines += ["", "Configurations: S0 none, S1 +history, S2 +Suricata, S3 +IP, S4 +audit, t2/t3/t4 single tool. "
              "Haiku: choices over its 3 runs (e.g. S3x2 = chosen in 2 runs).", ""]
    for (model, mode, lam), rows in support.items():
        lines += [f"## {P.NAME[model]}, cells = {mode}, lambda = {lam}", "",
                  "| held-out host | T (per run) | cell (signature / burst) | train alerts | malicious | selected |",
                  "|---|---|---|---|---|---|"]
        lines += [f"| {h} | {T} | {k} | {n} | {nm} | {ch} |" for h, k, T, n, nm, ch in rows]
        lines.append("")
    open(os.path.join(P.BASE, "results", "ablation_p2.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines[:30]))


if __name__ == "__main__":
    main()
