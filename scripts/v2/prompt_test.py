"""Prompt-wording check for Setting C: are the results tied to the exact wording of the prompt?

The Setting C sample is triaged by Haiku once more with a reworded prompt: the system prompt and the
task are rewritten in different words and the fields of the alert case are given in a different order,
but they carry the same information (the same network description, the same prior that most alerts are
false positives, the same tools and evidence, the same answer format). The tool ladder, the single
tools and learned routing (P2) are then compared with the three runs of the original prompt.

Usage: .venv/bin/python scripts/v2/prompt_test.py run|report|preview
Output: outputs/promptC_<model>.jsonl, results/prompt_test.md
"""
import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import analyze_C as C  # noqa: E402
import tools_v2  # noqa: E402
from triage import ask, parse_verdict  # noqa: E402
from triage_v2 import CONDITIONS, evidence  # noqa: E402

BASE = os.path.join(HERE, "..", "..")

SYSTEM2 = """Your job is alert triage for a small organisation. Its network consists of a firewall, \
a DNS server, a VPN gateway, file shares, mail servers, and web servers that host WordPress and a \
webmail service. Alerts come from two sources: Wazuh on the hosts and Suricata on the network. \
The large majority of alerts are harmless and are triggered by ordinary activity of users and systems. \
For the case below, judge whether it is an actual attack, taking into account any extra evidence provided."""

TASK2 = """Case summary
- Rule: {desc} (rule {rule}, level {level})
- Host: {host}
- Traffic: from {src} to {dst}
- Time window (UTC): {start} to {end}, {n} alerts

Sample log lines:
{examples}

{evidence}

Answer with a single JSON object and nothing else:
{{"verdict": "malicious" | "benign",
  "attack_type": "<brief label such as data exfiltration, password cracking, network scan, reverse shell, \
web vulnerability scan, privilege escalation, webshell, or none>",
  "confidence": <number from 0.0 to 1.0: probability that the case is malicious>,
  "reason": "<a single sentence>"}}"""


def build_prompt2(case, names, cache=None):
    ex = case["examples"] or [f"(network alert) {case['desc']} {case['src']} -> {case['dst']}"]
    ev = evidence(case, names, cache)[0]
    ev = ev.replace("No additional evidence is available.", "No further evidence was collected.")
    ev = ev.replace("Additional evidence:", "Further evidence:").replace("Evidence from tool", "Output of tool")
    return TASK2.format(host=case["host"], desc=case["desc"], rule=case["rule"], level=case["level"],
                        src=case["src"] or "-", dst=case["dst"] or "-", n=case["n_alerts"],
                        start=tools_v2.fmt(case["start"]), end=tools_v2.fmt(case["end"]),
                        examples="\n".join("  " + e[:220] for e in ex), evidence=ev)


def out_path(model):
    return os.path.join(BASE, "outputs", f"promptC_{model}.jsonl")


def run(args):
    path = out_path(args.model)
    done = {(r["case_id"], r["condition"]) for r in map(json.loads, open(path))} if os.path.exists(path) else set()
    jobs = []
    for c in sorted(C.SAMPLE):
        cache = {}
        for k in args.conditions:
            if (c, k) not in done:
                jobs.append((C.CASES[c], k, cache))
    print(f"{len(jobs)} calls -> {path}", flush=True)

    def one(job):
        case, k, cache = job
        text, stop, tin, tout = ask(args.model, build_prompt2(case, CONDITIONS[k], cache), "medium", system=SYSTEM2)
        v = parse_verdict(text)
        return {"case_id": case["case_id"], "condition": k, "truth": case["truth"],
                "verdict": v["verdict"] if v else None, "reason": v.get("reason") if v else None,
                "prompt_tokens": tin, "output_tokens": tout, "stop_reason": stop, "raw": text}

    with open(path, "a") as f, ThreadPoolExecutor(8) as pool:
        for i, rec in enumerate(pool.map(one, jobs)):
            f.write(json.dumps(rec) + "\n")
            f.flush()
            if i % 500 == 0:
                print(i, flush=True)


def report(model="claude-haiku-5-5"):
    ids = set(C.SAMPLE)
    orig = C.runs(model, ids)
    new = C.defaultdict(dict)
    for r in map(json.loads, open(out_path(model))):
        if r["case_id"] in ids:
            new[r["case_id"]][r["condition"]] = r
    conds = [k for k in CONDITIONS if all(k in orig[0][c] for c in orig[0])]
    complete = all(k in new[c] for c in ids for k in conds)
    conds_new = [k for k in conds if all(k in new[c] for c in ids)]
    L = [f"# Prompt-wording check (Setting C, {model})", "",
         f"{len(ids)} cases; original prompt = mean (min-max) over {len(orig)} runs; reworded prompt = one run"
         + ("" if complete else " (INCOMPLETE)") + ".",
         "Agreement = share of cases with the same verdict as original run 1 (original: runs 2 and 3 vs run 1).", "",
         "| configuration | BA original | BA reworded | det. orig / reworded | FA orig / reworded | agreement orig. runs | agreement reworded |",
         "|---|---|---|---|---|---|---|"]
    r1 = orig[0]
    unparsed = sum(r["verdict"] is None for c in new for r in new[c].values())
    for k in conds:
        if not all(k in new[c] for c in ids):
            continue
        so = [C.score(C.fixed(model, r, k)) for r in orig]
        sn = C.score(C.fixed(model, new, k))
        ag_o = [100 * np.mean([C.said(r[c][k]) == C.said(r1[c][k]) for c in ids]) for r in orig[1:]]
        ag_n = 100 * np.mean([C.said(new[c][k]) == C.said(r1[c][k]) for c in ids])
        ba = [s["ba"] for s in so]
        L.append(f"| {k} | {np.mean(ba):.1f} ({min(ba):.1f}-{max(ba):.1f}) | {sn['ba']:.1f} | "
                 f"{np.mean([s['det'] for s in so]):.1f} / {sn['det']} | {np.mean([s['fa'] for s in so]):.1f} / {sn['fa']} | "
                 f"{'-'.join(f'{a:.1f}' for a in ag_o)}% | {ag_n:.1f}% |")
    if complete:
        po = [C.score([d[:4] for d in C.routing(model, r, 0.05, conds)]) for r in orig]
        pn = C.score([d[:4] for d in C.routing(model, new, 0.05, conds)])
        ba = [s["ba"] for s in po]
        L.append(f"| P2 routing (lambda=0.05) | {np.mean(ba):.1f} ({min(ba):.1f}-{max(ba):.1f}) | {pn['ba']:.1f} | "
                 f"{np.mean([s['det'] for s in po]):.1f} / {pn['det']} | {np.mean([s['fa'] for s in po]):.1f} / {pn['fa']} | - | - |")
        L.append(f"| P2 cost ($ per 1k cases) | {np.mean([s['cost'] for s in po]):.2f} | {pn['cost']:.2f} | | | | |")
    L += ["", f"Unparsed answers in the reworded run (counted as malicious): {unparsed}"]
    # per alert type of the attacks: detections orig (mean) vs reworded, all tools
    k = "L4_+host"
    if all(k in new[c] for c in ids):
        by = C.defaultdict(list)
        for c in ids:
            if C.CASES[c]["truth"]:
                by[C.CASES[c]["desc"]].append(c)
        L += ["", "## Attacks detected per alert type, all tools (original mean / reworded)", "",
              "| alert type | cases | original | reworded |", "|---|---|---|---|"]
        for d, cs in sorted(by.items(), key=lambda x: -len(x[1])):
            o = np.mean([sum(C.said(r[c][k]) for c in cs) for r in orig])
            L.append(f"| {d[:70]} | {len(cs)} | {o:.1f} | {sum(C.said(new[c][k]) for c in cs)} |")
    open(os.path.join(BASE, "results", "prompt_test.md" if model == "claude-haiku-5-5" else f"prompt_test_{model}.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["run", "report", "preview"])
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--conditions", nargs="*", default=list(CONDITIONS))
    a = ap.parse_args()
    if a.what == "run":
        run(a)
    elif a.what == "preview":
        c = C.CASES[sorted(C.SAMPLE)[0]]
        print("=== SYSTEM ===\n" + SYSTEM2 + "\n\n=== USER ===\n" + build_prompt2(c, CONDITIONS["L2_+context"]))
    else:
        report(a.model)
