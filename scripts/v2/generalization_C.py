"""Setting C: does learned routing (P2) transfer to alert signatures and attack steps not seen in training?

All splits are leave-one-scenario-out (test network never in training) and additionally remove from training
  - seen:        nothing (as in the paper)
  - unseen sig:  every case with the test case's signature (leave-one-signature-out)
  - unseen step: every case whose signature belongs to the test case's attack step (leave-one-step-out)
Two policies: "sig" = signature only (unseen signature -> IP activity); "backoff" = signature -> log-source family
(from the Wazuh rule file) -> all training cases, with class-balanced errors at the fallback levels;
"all" = signature only, unseen signature -> all tools (safe default).
Also: how often the best tool set of a signature differs between networks.

Usage: .venv/bin/python scripts/v2/generalization_C.py  ->  results/generalization_C.md
"""
import os
import sys
from collections import Counter, defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.argv = sys.argv[:1]
import analyze_C as A  # noqa: E402

LAM = 0.05
IDS = set(l.strip() for l in open(os.path.join(A.BASE, "alerts_v2", "sample_C_gemini.txt")) if l.strip())
C = A.CASES


def family(c):
    """Log source of the alert, from the Wazuh rule file its rule id belongs to."""
    r = int(C[c]["rule"])
    if r == 86601:
        return "suricata"
    if 30000 <= r < 32000:
        return "web"
    if 9700 <= r < 9800:
        return "mail"
    if r < 6000:
        return "system"
    return "other"


# attack step of each signature that has malicious cases (majority AIT-LDS phase label)
STEP_OF_PHASE = {"service_scans": "scan", "service_scan": "scan", "wpscan": "web", "dirb": "web", "foothold": "web",
                 "attacker_http": "web", "cracking": "cracking", "escalate": "escalation",
                 "escalated_command": "escalation", "attacker_change_user": "escalation", "dnsteal": "exfiltration"}


def steps():
    votes = defaultdict(Counter)
    for c in IDS:
        if C[c]["truth"]:
            labels = C[c]["labels"]
            for p in (eval(labels) if isinstance(labels, str) else labels):
                if p in STEP_OF_PHASE:
                    votes[C[c]["desc"]][STEP_OF_PHASE[p]] += 1
    return {d: v.most_common(1)[0][0] for d, v in votes.items()}


STEP = steps()


def choose(model, run, cs, conds, base, balanced=False):
    """Condition minimising errors + LAM * relative cost; balanced: errors on attacks and benign cases weighted
    equally (as in balanced accuracy), used for the fallback levels, whose cases are mostly benign."""
    nm = sum(C[c]["truth"] for c in cs)
    w = {True: len(cs) / (2 * max(nm, 1)), False: len(cs) / (2 * max(len(cs) - nm, 1))} if balanced else {True: 1, False: 1}
    return min(conds, key=lambda k: sum(w[run[c][k]["truth"]] * (A.said(run[c][k]) != run[c][k]["truth"])
                                        + LAM * A.cost(model, run[c][k]) / base for c in cs))


def route(model, run, conds, split, policy):
    """Decisions for every case; training set = other scenarios minus what `split` removes."""
    out = []
    groups = defaultdict(list)  # cases sharing one training set
    for c in run:
        d = C[c]["desc"]
        key = (C[c]["scenario"], None if split == "seen" else d if split == "sig" else STEP.get(d, d))
        groups[key].append(c)
    for (test, held), tcs in groups.items():
        train = [c for c in run if C[c]["scenario"] != test and
                 (held is None or (C[c]["desc"] if split == "sig" else STEP.get(C[c]["desc"], C[c]["desc"])) != held)]
        base = sum(A.cost(model, run[c]["L0_none"]) for c in train) / len(train)
        by_sig, by_fam = defaultdict(list), defaultdict(list)
        for c in train:
            by_sig[C[c]["desc"]].append(c)
            by_fam[family(c)].append(c)
        memo = {}
        for c in tcs:
            d, f = C[c]["desc"], family(c)
            if d in by_sig:
                lvl, cs = ("sig", d), by_sig[d]
            elif policy in ("sig", "all"):
                lvl, cs = ("fixed", None), None
            elif f in by_fam:
                lvl, cs = ("fam", f), by_fam[f]
            else:
                lvl, cs = ("all", None), train
            if lvl not in memo:
                memo[lvl] = ({"sig": "only_ip", "all": "L4_+host"}[policy] if lvl[0] == "fixed"
                             else choose(model, run, cs, conds, base, lvl[0] != "sig"))
            k = memo[lvl]
            r = run[c][k]
            out.append((A.said(r), r["truth"], A.cost(model, r), bool(A.EXPENSIVE & set(A.CONDITIONS[k])), c, k))
    return out


def instability(model, run, conds):
    """Signatures with malicious cases in >= 2 networks: does the per-network best tool set differ?"""
    rows = []
    for d in sorted({C[c]["desc"] for c in run if C[c]["truth"]}):
        per = defaultdict(list)
        for c in run:
            if C[c]["desc"] == d:
                per[C[c]["scenario"]].append(c)
        if len(per) < 2:
            continue
        base = sum(A.cost(model, run[c]["L0_none"]) for cs in per.values() for c in cs) / sum(map(len, per.values()))
        best = {s: choose(model, run, cs, conds, base) for s, cs in per.items()}
        rows.append((d, len(set(best.values())) > 1))
    return rows


def hindsight(model, run, conds):
    """BA if the tool set were chosen per (signature, network) on the test cases themselves."""
    base = sum(A.cost(model, run[c]["L0_none"]) for c in run) / len(run)
    per = defaultdict(list)
    for c in run:
        per[(C[c]["desc"], C[c]["scenario"])].append(c)
    decs = []
    for cs in per.values():
        k = choose(model, run, cs, conds, base)
        decs += [(A.said(run[c][k]), run[c][k]["truth"], A.cost(model, run[c][k]), False) for c in cs]
    return A.score(decs)["ba"]


def main():
    L = ["# Setting C: routing on seen vs unseen signatures and attack steps", "",
         f"Leave-one-scenario-out throughout; lambda={LAM}; mean over runs. 'sig' = paper P2 (unseen signature -> IP activity),",
         "'backoff' = signature -> log-source family -> all training cases (class-balanced errors at fallback levels).", "",
         "Attack steps: " + "; ".join(f"{s}: {sum(1 for v in STEP.values() if v == s)} signatures" for s in sorted(set(STEP.values()))), "",
         "| model | training excludes | policy | det | FA | BA | $ per 1k | det by step (scan/web/cracking/escalation/exfil) |",
         "|---|---|---|---|---|---|---|---|"]
    stepn = Counter(STEP.get(C[c]["desc"]) for c in IDS if C[c]["truth"])
    order = ["scan", "web", "cracking", "escalation", "exfiltration"]
    L2 = []
    for m in A.PRICE:
        rs = A.runs(m, IDS)
        if not rs:
            continue
        conds = [k for k in A.CONDITIONS if all(k in rs[0][c] for c in rs[0])]
        for k in ["L0_none", "L4_+host", "only_ip"]:
            if k not in conds:
                continue
            decs = [[d + (c, k) for d, c in zip(A.fixed(m, r, k), r)] for r in rs]
            L.append(row(m, "-", f"fixed {k}", decs, order))
        for split, pols in [("seen", ["sig"]), ("sig", ["sig", "backoff", "all"]), ("step", ["sig", "backoff", "all"])]:
            for pol in pols:
                decs = [route(m, r, conds, split, pol) for r in rs]
                L.append(row(m, {"seen": "test network", "sig": "+ test signature", "step": "+ test attack step"}[split],
                             pol, decs, order))
        inst = [instability(m, r, conds) for r in rs]
        n = len(inst[0])
        L2.append(f"| {A.NAME[m]} | {n} | {np.mean([sum(x for _, x in i) for i in inst]):.1f} | "
                  f"{np.mean([hindsight(m, r, conds) for r in rs]):.1f} | "
                  f"{np.mean([A.score([d[:4] for d in route(m, r, conds, 'seen', 'sig')])['ba'] for r in rs]):.1f} | "
                  + ", ".join(d for d, x in inst[0] if x) + " |")
    L += ["", f"Attacks per step: " + ", ".join(f"{s} {stepn[s]}" for s in order), "",
          "## Does the best tool set of a signature differ between networks?", "",
          "Hindsight = tool set chosen per signature and network on the test cases themselves (in-sample upper bound).", "",
          "| model | signatures in >= 2 networks | best set differs (mean over runs) | BA hindsight | BA P2 | which (run 1) |",
          "|---|---|---|---|---|---|"] + L2
    out = os.path.join(A.BASE, "results", "generalization_C.md")
    open(out, "w").write("\n".join(L) + "\n")
    print("\n".join(L))


def row(m, split, pol, decs, order):
    sc = A.mean([A.score([d[:4] for d in ds]) for ds in decs])
    by = [np.mean([sum(d[0] for d in ds if d[1] and STEP.get(C[d[4]]["desc"]) == s) for ds in decs]) for s in order]
    return (f"| {A.NAME[m]} | {split} | {pol} | {sc['det']:.1f} | {sc['fa']:.1f} | {sc['ba']:.1f} | {sc['cost']:.2f} | "
            + "/".join(f"{x:.1f}" for x in by) + " |")


if __name__ == "__main__":
    main()
