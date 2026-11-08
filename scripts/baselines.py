"""Non-LLM triage baselines on Setting A (no API calls).

B1 IDS priority   escalate alerts whose Suricata priority is 1 (or all alerts)
B2 rarity         NoDoze-style frequency triage (Hassan et al. 2019), unsupervised:
                  escalate if the burst ratio (alarms of the case + other alarms from the same
                  source in the 30 min before, divided by 1 + mean daily rate of this
                  signature from this source on previous days) exceeds T; T chosen
                  leave-one-host-out
B3 supervised     decision tree / random forest on alarm-stream features, trained on three
                  hosts with labels and applied to the fourth (leave-one-host-out)

Features use only the alarm stream up to the case end, like the cheap evidence of P2.
Usage: .venv/bin/python scripts/baselines.py  ->  results/baselines.md
"""
import json
import math
import os
from collections import defaultdict
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

import tools

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CASES = [json.loads(l) for l in open(os.path.join(BASE, "alerts", "cases.jsonl"))]
KEEP = {l.strip() for l in open(os.path.join(BASE, "alerts", "sample_claude.txt")) if l.strip()}
HOSTS = sorted({c["host"] for c in CASES})


def alarm_features():
    """Per case: n_alarms, other alarms from src in 30 min before, mean daily rate of
    (signature, src) on previous days, mean daily rate of signature on previous days,
    distinct signatures from src in 30 min before, hour of day."""
    by_host = defaultdict(list)
    for c in CASES:
        by_host[c["host"]].append(c)
    feats = {}
    for host, cases in by_host.items():
        stream = []
        for ts, text in tools.suricata_alerts(host):
            m = tools.SIG_RE.search(text)
            if m:
                stream.append((ts, m.group(1), m.group(2)))
        for c in cases:
            start, end = datetime.fromisoformat(c["start"]), datetime.fromisoformat(c["end"])
            pair_day, sig_day, days, other, other_sigs = defaultdict(int), defaultdict(int), set(), 0, set()
            for ts, sig, src in stream:
                if ts > end:
                    break
                if ts.date() < start.date():
                    days.add(ts.date())
                    if sig == c["signature"]:
                        sig_day[ts.date()] += 1
                        if src == c["src_ip"]:
                            pair_day[ts.date()] += 1
                elif start - timedelta(minutes=30) <= ts < start and src == c["src_ip"]:
                    other += 1
                    other_sigs.add(sig)
            nd = max(len(days), 1)
            pair_rate, sig_rate = sum(pair_day.values()) / nd, sum(sig_day.values()) / nd
            feats[c["case_id"]] = {
                "n_alarms": c["n_alarms"], "other": other, "pair_rate": pair_rate,
                "sig_rate": sig_rate, "other_sigs": len(other_sigs), "hour": start.hour,
                "burst": (c["n_alarms"] + other) / (1.0 + pair_rate)}
    return feats


def score(pairs):
    att = [p for p in pairs if p[1]]
    ben = [p for p in pairs if not p[1]]
    tp, fp = sum(p[0] for p in att), sum(p[0] for p in ben)
    return tp, len(att), fp, len(ben), 50 * (tp / len(att) + 1 - fp / len(ben))


def ba(pairs):
    return score(pairs)[4]


def loho(cases, predict_fold):
    """predict_fold(train, test) -> list of bool predictions for test."""
    out = []
    for h in HOSTS:
        train = [c for c in cases if c["host"] != h]
        test = [c for c in cases if c["host"] == h]
        out += list(zip(predict_fold(train, test), [c["truth"] for c in test]))
    return out


def matrix(cases, F, sigs):
    rows = []
    for c in cases:
        f = F[c["case_id"]]
        rows.append([math.log1p(f["n_alarms"]), math.log1p(f["other"]), math.log1p(f["pair_rate"]),
                     math.log1p(f["sig_rate"]), f["other_sigs"], f["hour"], c["priority"],
                     math.log1p(f["burst"])] + [float(c["signature"] == s) for s in sigs])
    return np.array(rows)


def main():
    F = alarm_features()
    sigs = sorted({c["signature"] for c in CASES})
    lines = ["# Non-LLM baselines (Setting A, leave-one-host-out)", "",
             "| baseline | cases | detected | false alarms | balanced acc. |", "|---|---|---|---|---|"]
    for name, cases in [("175 sample", [c for c in CASES if c["case_id"] in KEEP]), ("all 589", CASES)]:
        rows = []
        rows.append(("B0 escalate every alert", [(True, c["truth"]) for c in cases]))
        rows.append(("B1 IDS priority 1 only", [(c["priority"] == 1, c["truth"]) for c in cases]))
        rows.append(("B1 IDS priority >= 2 only", [(c["priority"] >= 2, c["truth"]) for c in cases]))

        def rarity(train, test):
            T = max([1, 2, 5, 10, 20, 50], key=lambda t: ba([(F[c["case_id"]]["burst"] > t, c["truth"]) for c in train]))
            return [F[c["case_id"]]["burst"] > T for c in test]
        rows.append(("B2 rarity / burst (unsupervised, T by LOHO)", loho(cases, rarity)))

        def model(make):
            def fold(train, test):
                clf = make().fit(matrix(train, F, sigs), [c["truth"] for c in train])
                return list(clf.predict(matrix(test, F, sigs)).astype(bool))
            return fold
        rows.append(("B3 decision tree (supervised)", loho(cases, model(
            lambda: DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=0)))))
        rows.append(("B3 random forest (supervised)", loho(cases, model(
            lambda: RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)))))
        for label, pairs in rows:
            tp, na, fp, nb, b = score(pairs)
            lines.append(f"| {label} | {name} | {tp}/{na} | {fp}/{nb} | {b:.1f} |")
        # the hard signature only
        hard = [c for c in cases if "pass= in cleartext" in c["signature"]]
        for label, fold in [("B2 rarity", rarity), ("B3 random forest", model(
                lambda: RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)))]:
            preds = []
            for h in HOSTS:
                train = [c for c in cases if c["host"] != h]
                test = [c for c in hard if c["host"] == h]
                if test:
                    preds += list(zip(fold(train, test), [c["truth"] for c in test]))
            tp, na, fp, nb, b = score(preds)
            lines.append(f"| {label}, cleartext-password signature only | {name} | {tp}/{na} | {fp}/{nb} | {b:.1f} |")
    # per held-out host, all 589 cases
    lines += ["", "# Per held-out host (all 589 cases): detected/attacks, false alarms/benign, BA", "",
              "| baseline | " + " | ".join(h.split(".")[1] for h in HOSTS) + " |", "|---|" + "---|" * len(HOSTS)]
    for label, fold in [("B2 rarity / burst", rarity), ("B3 random forest", model(
            lambda: RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)))]:
        cells = []
        for h in HOSTS:
            train = [c for c in CASES if c["host"] != h]
            test = [c for c in CASES if c["host"] == h]
            tp, na, fp, nb, b = score(list(zip(fold(train, test), [c["truth"] for c in test])))
            cells.append(f"{tp}/{na}, {fp}/{nb}, {b:.1f}")
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    open(os.path.join(BASE, "results", "baselines.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
