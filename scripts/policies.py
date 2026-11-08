"""Per-alert tool-selection policies vs. fixed tool configurations (Setting A).

Fixed      every alert gets the same tool set (L0..L4, single tools)
P1 escal.  confidence-gated escalation along the ladder: stop when the model's
           confidence is outside [lo, hi], else call the next tool (cost of every call counted)
P2 route   alert-type routing: for each signature, the tool set with the fewest errors
           (ties: cheapest) on the OTHER three hosts; leave-one-host-out
P3 adapt.  the model chooses its own tools within a budget (triage_adaptive.py)
P5 stop.   learned cost-aware stopping: cell = (signature, burst of cheap alarm-stream
           evidence); per cell the tool set minimising errors + lambda * cost on the
           training hosts; leave-one-host-out (cf. Feng et al. 2026, Lee et al. 2002)
P4 casc.   model cascade: Haiku + IP activity; escalate to Opus + IP activity when
           Haiku's confidence is in [lo, hi]

Computed from the existing per-condition answers (no new LLM calls) except P3.
Usage: .venv/bin/python scripts/policies.py [--all]  ->  results/policies{,_all}.md, results/policies{,_all}.csv,
       results/per_host{,_all}.md
"""
import csv
import glob
import json
import os
import sys
from collections import defaultdict

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRICE = {"claude-haiku-5-5": (0.1e-6, 0.5e-6), "claude-opus-5-5": (4e-6, 20e-6)}
NAME = {"claude-haiku-5-5": "Haiku 5.5", "claude-opus-5-5": "Opus 5.5"}
LADDER = ["L0_none", "L1_history", "L2_+suricata", "L3_+ip", "L4_+audit"]
CONDS = LADDER + ["only_suricata", "only_ip", "only_audit"]
EXPENSIVE = {"ip_history", "audit_exec"}
COND_TOOLS = {"L0_none": [], "L1_history": ["alert_history"], "L2_+suricata": ["alert_history", "suricata"],
              "L3_+ip": ["alert_history", "suricata", "ip_history"],
              "L4_+audit": ["alert_history", "suricata", "ip_history", "audit_exec"],
              "only_suricata": ["suricata"], "only_ip": ["ip_history"], "only_audit": ["audit_exec"]}
CASES = {c["case_id"]: c for c in map(json.loads, open(os.path.join(BASE, "alerts", "cases.jsonl")))}
ALL = "--all" in sys.argv  # evaluate on all 589 cases instead of the 175-case sample
KEEP = set(CASES) if ALL else {l.strip() for l in open(os.path.join(BASE, "alerts", "sample_claude.txt")) if l.strip()}
TAG = "_all" if ALL else ""


def said_mal(r):
    return (r["verdict"] or "malicious") == "malicious"


def cost(model, r):
    p = PRICE[model]
    return (r["prompt_tokens"] * p[0] + r["output_tokens"] * p[1]) * 1000  # $ per 1k alerts


def runs_of(model):
    """List of runs; each run: case_id -> condition -> record."""
    out = []
    for path in sorted(glob.glob(os.path.join(BASE, "outputs", f"triage_{model}*.jsonl"))):
        run = defaultdict(dict)
        for r in map(json.loads, open(path)):
            if r["case_id"] in KEEP:
                run[r["case_id"]][r["condition"]] = r
        if len(run) == len(KEEP):
            out.append(run)
    return out


def score(decisions):
    """decisions: list of (said_malicious, truth, cost, n_tool_calls, used_expensive)."""
    att = [d for d in decisions if d[1]]
    ben = [d for d in decisions if not d[1]]
    tp = sum(d[0] for d in att)
    fp = sum(d[0] for d in ben)
    n = len(decisions)
    return {"det": tp, "n_att": len(att), "fa": fp, "n_ben": len(ben),
            "ba": 50 * (tp / len(att) + 1 - fp / len(ben)),
            "cost": sum(d[2] for d in decisions) / n,
            "calls": sum(d[3] for d in decisions) / n,
            "expensive": 100 * sum(d[4] for d in decisions) / n}


def fixed(model, run, cond):
    tools = COND_TOOLS[cond]
    return [(said_mal(run[c][cond]), run[c][cond]["truth"], cost(model, run[c][cond]),
             len(tools), bool(EXPENSIVE & set(tools))) for c in run]


def escalation(model, run, lo, hi):
    out = []
    for c in run:
        total, used = 0.0, set()
        for k, cond in enumerate(LADDER):
            r = run[c][cond]
            total += cost(model, r)
            used |= set(COND_TOOLS[cond])
            conf = r["confidence"] if r["confidence"] is not None else 0.5
            if not lo <= conf <= hi or k == len(LADDER) - 1:
                out.append((said_mal(r), r["truth"], total, len(COND_TOOLS[cond]), bool(EXPENSIVE & used)))
                break
    return out


def routing(model, run):
    out = []
    hosts = {CASES[c]["host"] for c in run}
    for test in hosts:
        train = [c for c in run if CASES[c]["host"] != test]
        choice = {}
        for sig in {CASES[c]["signature"] for c in run}:
            tc = [c for c in train if CASES[c]["signature"] == sig]
            if not tc:
                choice[sig] = "only_ip"  # unseen signature: best single tool overall
                continue
            def key(cond):
                errors = sum(said_mal(run[c][cond]) != run[c][cond]["truth"] for c in tc)
                return (errors, sum(cost(model, run[c][cond]) for c in tc))
            choice[sig] = min(CONDS, key=key)
        for c in run:
            if CASES[c]["host"] == test:
                cond = choice[CASES[c]["signature"]]
                r = run[c][cond]
                out.append((said_mal(r), r["truth"], cost(model, r), len(COND_TOOLS[cond]),
                            bool(EXPENSIVE & set(COND_TOOLS[cond]))))
    return out


# ------------------------------------------------------------------ P5
_FEATS = None


def features():
    """Cheap deterministic evidence per case, computed from the alarm stream only
    (no LLM call): burst ratio = (alarms in the case + other alarms from the same
    source in the 30 min before) / (1 + normal daily rate of this alarm from this source)."""
    global _FEATS
    if _FEATS is not None:
        return _FEATS
    import re
    from datetime import datetime, timedelta
    import tools
    _FEATS = {}
    for cid in KEEP:
        c = CASES[cid]
        start, end = datetime.fromisoformat(c["start"]), datetime.fromisoformat(c["end"])
        per_day, days, other = defaultdict(int), set(), 0
        for ts, text in tools.suricata_alerts(c["host"]):
            if ts > end:
                break
            m = tools.SIG_RE.search(text)
            if not m:
                continue
            if ts.date() < start.date():
                days.add(ts.date())
                if m.group(1) == c["signature"] and m.group(2) == c["src_ip"]:
                    per_day[ts.date()] += 1
            elif ts >= start - timedelta(minutes=30) and ts < start and c["src_ip"] in text:
                other += 1
        rate = sum(per_day.values()) / max(len(days), 1)
        _FEATS[cid] = (c["n_alarms"] + other) / (1.0 + rate)
    return _FEATS


THRESHOLDS = [2, 5, 10, 20]


def stopping(model, run, lam):
    """P5: learned cost-aware stopping. Each alert falls into a cell (signature, z) with
    z = 1[burst ratio > T]; for every cell the tool set minimising errors + lam * relative
    cost (cost / mean no-tool cost of the model) on the training hosts is bought. T is chosen on the training hosts as well.
    Leave-one-host-out; cost in $ per 1k alerts."""
    feats = features()
    out = []
    hosts = {CASES[c]["host"] for c in run}
    for test in hosts:
        train = [c for c in run if CASES[c]["host"] != test]

        # cost relative to the mean no-tool cost of this model on the training hosts,
        # so lambda means the same for every model: 1 unit = one no-tool LLM call
        base = sum(cost(model, run[c]["L0_none"]) for c in train) / len(train)

        def fit(T):
            cells = defaultdict(list)
            for c in train:
                cells[(CASES[c]["signature"], feats[c] > T)].append(c)
            choice, loss = {}, 0.0
            for cell, cs in cells.items():
                def obj(cond):
                    return sum((said_mal(run[c][cond]) != run[c][cond]["truth"])
                               + lam * cost(model, run[c][cond]) / base for c in cs)
                choice[cell] = min(CONDS, key=obj)
                loss += obj(choice[cell])
            return loss, choice

        T, (_, choice) = min(((T, fit(T)) for T in THRESHOLDS), key=lambda x: x[1][0])
        for c in run:
            if CASES[c]["host"] != test:
                continue
            z = feats[c] > T
            cond = choice.get((CASES[c]["signature"], z)) or choice.get((CASES[c]["signature"], not z)) or "only_ip"
            r = run[c][cond]
            out.append((said_mal(r), r["truth"], cost(model, r), len(COND_TOOLS[cond]),
                        bool(EXPENSIVE & set(COND_TOOLS[cond])), c))
    return out


def cascade(cheap_run, big_run, lo, hi, cond="only_ip"):
    out = []
    for c in cheap_run:
        r = cheap_run[c][cond]
        total = cost("claude-haiku-5-5", r)
        conf = r["confidence"] if r["confidence"] is not None else 0.5
        if lo <= conf <= hi:
            r = big_run[c][cond]
            total += cost("claude-opus-5-5", r)
        out.append((said_mal(r), r["truth"], total, len(COND_TOOLS[cond]), True))
    return out


def adaptive(model):
    res = []
    for path in sorted(glob.glob(os.path.join(BASE, "outputs", f"adaptive_A_{model}*.jsonl"))):
        recs = {r["case_id"]: r for r in map(json.loads, open(path)) if r["case_id"] in KEEP}
        if len(recs) == len(KEEP):
            res.append([(said_mal(r), r["truth"], cost(model, r), len(r["tools_called"]),
                         bool(EXPENSIVE & set(r["tools_called"]))) for r in recs.values()])
    return res


def setting_b_lines():
    """Setting B: fixed ladder steps vs. model-selected tools (no alert types to route on)."""
    out = ["", "# Setting B (vague alerts): fixed vs. model-selected tools", "",
           "| window | model | policy | runs | detected /27 | false alarms /28 | balanced acc. | $ per 1k alerts | tool calls / alert | alerts using IP or audit (%) |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    vtools = {"V1_overview": ["overview"], "V3_+ip": ["overview", "suricata", "ip_history"],
              "V4_+audit": ["overview", "suricata", "ip_history", "audit_exec"]}
    for w in ("30", "5"):
        for model in PRICE:
            for cond, tl in vtools.items():
                sc = []
                for path in sorted(glob.glob(os.path.join(BASE, "outputs", f"vague{w}_{model}*.jsonl"))):
                    recs = [r for r in map(json.loads, open(path)) if r["condition"] == cond]
                    sc.append(score([(said_mal(r), r["truth"], cost(model, r), len(tl),
                                      bool(EXPENSIVE & set(tl))) for r in recs]))
                if sc:
                    m = mean(sc)
                    out.append(f"| {w} min | {NAME[model]} | fixed: {cond} | {len(sc)} | {m['det']:.1f} | {m['fa']:.1f} | "
                               f"{m['ba']:.1f} | {m['cost']:.2f} | {m['calls']:.2f} | {m['expensive']:.0f} |")
            sc = []
            for path in sorted(glob.glob(os.path.join(BASE, "outputs", f"adaptive_B{w}_{model}*.jsonl"))):
                recs = list(map(json.loads, open(path)))
                sc.append(score([(said_mal(r), r["truth"], cost(model, r), len(r["tools_called"]),
                                  bool(EXPENSIVE & set(r["tools_called"]))) for r in recs]))
            if sc:
                m = mean(sc)
                out.append(f"| {w} min | {NAME[model]} | P3 model-selected tools | {len(sc)} | {m['det']:.1f} | {m['fa']:.1f} | "
                           f"{m['ba']:.1f} | {m['cost']:.2f} | {m['calls']:.2f} | {m['expensive']:.0f} |")
    return out


def per_host_lines():
    """Each held-out host separately: fixed configurations (all three models) and P5 (lambda=0.01, 0.05)."""
    hosts = sorted({CASES[c]["host"] for c in KEEP})
    short = [h.split(".")[1] for h in hosts]
    out = [f"# Per held-out host (Setting A, {len(KEEP)} cases): detected/attacks, false alarms/benign, BA", "",
           "| model | configuration | " + " | ".join(short) + " |", "|---|---|" + "---|" * len(hosts)]
    models = list(PRICE) + ["qwen2.5_14b"]
    for model in models:
        runs = runs_of(model)
        if not runs:
            continue
        configs = [(cond, lambda run, cond=cond: [(said_mal(run[c][cond]), run[c][cond]["truth"], c) for c in run])
                   for cond in ["L0_none", "L4_+audit", "only_ip"]]
        if model in PRICE:
            for lam in (0.01, 0.05):
                configs.append((f"P5 stopping (lambda={lam})",
                                lambda run, lam=lam: [(d[0], d[1], d[5]) for d in stopping(model, run, lam)]))
        for label, fn in configs:
            decs = [fn(run) for run in runs]
            cells = []
            for h in hosts:
                tp = sum(sum(d[0] for d in ds if d[1] and CASES[d[2]]["host"] == h) for ds in decs) / len(decs)
                fp = sum(sum(d[0] for d in ds if not d[1] and CASES[d[2]]["host"] == h) for ds in decs) / len(decs)
                na = sum(CASES[c]["truth"] for c in KEEP if CASES[c]["host"] == h)
                nb = sum(not CASES[c]["truth"] for c in KEEP if CASES[c]["host"] == h)
                ba = 50 * (tp / na + 1 - fp / nb)
                cells.append(f"{round(tp, 1):g}/{na}, {round(fp, 1):g}/{nb}, {ba:.1f}")
            out.append(f"| {NAME.get(model, 'qwen2.5-14B')} ({len(runs)} run{'s' if len(runs) > 1 else ''}) | {label} | "
                       + " | ".join(cells) + " |")
    return out


def mean(scores):
    return {k: sum(s[k] for s in scores) / len(scores) for k in scores[0]}


def main():
    rows = []
    for model in PRICE:
        runs = runs_of(model)
        for cond in ["L0_none", "L3_+ip", "L4_+audit", "only_ip"]:
            rows.append(("fixed: " + cond, model, len(runs), mean([score(fixed(model, r, cond)) for r in runs])))
        for lo, hi in [(0.2, 0.8), (0.1, 0.9)]:
            rows.append((f"P1 escalation [{lo},{hi}]", model, len(runs),
                         mean([score(escalation(model, r, lo, hi)) for r in runs])))
        rows.append(("P2 alert-type routing (LOHO)", model, len(runs), mean([score(routing(model, r)) for r in runs])))
        for lam in [0.0, 0.01, 0.05, 0.1, 0.25, 0.5]:
            rows.append((f"P5 cost-aware stopping (lambda={lam})", model, len(runs),
                         mean([score(stopping(model, r, lam)) for r in runs])))
        ad = adaptive(model)
        if ad:
            rows.append(("P3 model-selected tools", model, len(ad), mean([score(d) for d in ad])))
    haiku, opus = runs_of("claude-haiku-5-5"), runs_of("claude-opus-5-5")
    if haiku and opus:
        for lo, hi in [(0.2, 0.8), (0.1, 0.9)]:
            rows.append((f"P4 cascade Haiku->Opus [{lo},{hi}]", "cascade", len(haiku),
                         mean([score(cascade(h, o, lo, hi)) for h, o in zip(haiku, opus)] if len(opus) == len(haiku)
                              else [score(cascade(h, opus[0], lo, hi)) for h in haiku])))

    n_ben = sum(not CASES[c]["truth"] for c in KEEP)
    lines = [f"# Per-alert policies vs. fixed configurations (Setting A, {len(KEEP)} cases)", "",
             f"| policy | model | runs | detected /25 | false alarms /{n_ben} | balanced acc. | $ per 1k alerts | tool calls / alert | alerts using IP or audit (%) |",
             "|---|---|---|---|---|---|---|---|---|"]
    with open(os.path.join(BASE, "results", f"policies{TAG}.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["policy", "model", "runs", "det", "fa", "ba", "cost_per_1k", "calls", "expensive_pct"])
        for pol, model, n, s in rows:
            name = NAME.get(model, "Haiku->Opus")
            lines.append(f"| {pol} | {name} | {n} | {s['det']:.1f} | {s['fa']:.1f} | {s['ba']:.1f} | "
                         f"{s['cost']:.2f} | {s['calls']:.2f} | {s['expensive']:.0f} |")
            w.writerow([pol, name, n, round(s["det"], 2), round(s["fa"], 2), round(s["ba"], 2),
                        round(s["cost"], 3), round(s["calls"], 2), round(s["expensive"], 1)])
    if not ALL:
        lines += setting_b_lines()
    open(os.path.join(BASE, "results", f"policies{TAG}.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))
    ph = per_host_lines()
    open(os.path.join(BASE, "results", f"per_host{TAG}.md"), "w").write("\n".join(ph) + "\n")
    print("\n".join(ph))


if __name__ == "__main__":
    main()
