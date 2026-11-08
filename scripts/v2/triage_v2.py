"""Setting C: LLM triage of Wazuh/Suricata alert cases from AIT-LDS v2 (8 scenarios).

Same conditions as Setting A (ladder of four tools, plus single tools); the tools are the v2
versions in tools_v2.py. Every tool reads only data up to the end of the case.

  python3 scripts/v2/triage_v2.py --preview <case_id> --tools          # print a prompt, no LLM call
  .venv/bin/python scripts/v2/triage_v2.py --case-file alerts_v2/sample_C.txt --model claude-haiku-5-5
Output: outputs/triageC_<model>[_run<N>].jsonl (appends; finished case/condition pairs are skipped)
"""
import argparse
import glob
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import tools_v2  # noqa: E402
from triage import ask, parse_verdict  # noqa: E402

BASE = os.path.join(HERE, "..", "..")
LADDER = ["alert_history", "siem_context", "ip_activity", "host_activity"]
CONDITIONS = {
    "L0_none": [],
    "L1_history": LADDER[:1],
    "L2_+context": LADDER[:2],
    "L3_+ip": LADDER[:3],
    "L4_+host": LADDER[:4],
    "only_context": ["siem_context"],
    "only_ip": ["ip_activity"],
    "only_host": ["host_activity"],
}

SYSTEM = """You are a security analyst triaging alerts from the SIEM of a small company \
network (web servers with WordPress and webmail, mail servers, file shares, a VPN gateway, \
DNS and a firewall). The SIEM collects host-based alerts (Wazuh) and network alerts \
(Suricata). Most alerts are false positives caused by normal user and system activity. \
Decide whether this alert case is a real attack. Use the additional evidence if any is given."""

TASK = """Alert case on host {host}
Alert:          {desc} (rule {rule}, level {level})
Source -> dest: {src} -> {dst}
Alerts in case: {n}, from {start} to {end} (UTC)
Example log lines:
{examples}

{evidence}

Return JSON only, in this form:
{{"verdict": "malicious" or "benign",
  "attack_type": "<short name, e.g. network scan, web vulnerability scan, password cracking, \
webshell, reverse shell, privilege escalation, data exfiltration, none>",
  "confidence": <0.0-1.0, how sure you are that it is malicious>,
  "reason": "<one sentence>"}}"""


def load_cases():
    cases = {}
    for p in sorted(glob.glob(os.path.join(BASE, "alerts_v2", "cases_*.jsonl"))):
        for c in map(json.loads, open(p)):
            cases[c["case_id"]] = c
    return cases


def evidence(case, names, cache=None):
    if not names:
        return "No additional evidence is available.", 0.0
    cache = {} if cache is None else cache
    parts, secs = [], 0.0
    for t in names:
        if t not in cache:
            t0 = time.time()
            cache[t] = (tools_v2.TOOLS[t](case), time.time() - t0)
        parts.append(f"Evidence from tool '{t}':\n{cache[t][0]}")
        secs += cache[t][1]
    return "Additional evidence:\n\n" + "\n\n".join(parts), secs


def build_prompt(case, names, cache=None):
    ex = case["examples"] or [f"(network alert) {case['desc']} {case['src']} -> {case['dst']}"]
    return TASK.format(host=case["host"], desc=case["desc"], rule=case["rule"], level=case["level"],
                       src=case["src"] or "-", dst=case["dst"] or "-", n=case["n_alerts"],
                       start=tools_v2.fmt(case["start"]), end=tools_v2.fmt(case["end"]),
                       examples="\n".join("  " + e[:220] for e in ex),
                       evidence=evidence(case, names, cache)[0])


def run_one(case, condition, cache, args):
    names = CONDITIONS[condition]
    ev, tool_secs = evidence(case, names, cache)
    prompt = build_prompt(case, names, cache)
    t0 = time.time()
    text, stop, tin, tout = ask(args.model, prompt, args.effort, system=SYSTEM)
    v = parse_verdict(text)
    return {"case_id": case["case_id"], "scenario": case["scenario"], "condition": condition, "tools": names,
            "model": args.model, "truth": case["truth"], "desc": case["desc"],
            "verdict": v["verdict"] if v else None,
            "confidence": float(v["confidence"]) if v and isinstance(v.get("confidence"), (int, float)) else None,
            "attack_type": v.get("attack_type") if v else None, "reason": v.get("reason") if v else None,
            "evidence_chars": len(ev), "tool_seconds": round(tool_secs, 2),
            "prompt_tokens": tin, "output_tokens": tout, "llm_seconds": round(time.time() - t0, 1),
            "stop_reason": stop, "raw": text}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preview")
    ap.add_argument("--tools", nargs="*")
    ap.add_argument("--case-file")
    ap.add_argument("--cases", nargs="*")
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--effort", default="medium")
    ap.add_argument("--conditions", nargs="*", default=list(CONDITIONS))
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--run", type=int, default=1)
    args = ap.parse_args()
    cases = load_cases()
    if args.preview:
        names = [] if args.tools is None else (args.tools or LADDER)
        print("=== SYSTEM ===\n" + SYSTEM + "\n\n=== USER ===\n" + build_prompt(cases[args.preview], names))
        print(f"\n=== GROUND TRUTH (hidden) === malicious={cases[args.preview]['truth']} {cases[args.preview]['labels']}")
        return
    ids = [l.strip() for l in open(args.case_file) if l.strip()] if args.case_file else (args.cases or [])
    suffix = "" if args.run == 1 else f"_run{args.run}"
    out_path = os.path.join(BASE, "outputs", f"triageC_{args.model.replace(':', '_').replace('/', '_')}{suffix}.jsonl")
    done = set()
    if os.path.exists(out_path):
        done = {(r["case_id"], r["condition"]) for r in map(json.loads, open(out_path))}
    jobs = []
    for cid in ids:
        cache = {}
        for cond in args.conditions:
            if (cid, cond) not in done:
                evidence(cases[cid], CONDITIONS[cond], cache)
                jobs.append((cases[cid], cond, cache))
    print(f"{len(ids)} cases, {len(jobs)} calls -> {os.path.relpath(out_path, BASE)}", flush=True)
    workers = args.workers if (args.model.startswith(("claude-", "gemini-")) or "/" in args.model) else 1
    with open(out_path, "a") as f, ThreadPoolExecutor(workers) as pool:
        for rec in pool.map(lambda j: run_one(*j, args), jobs):
            f.write(json.dumps(rec) + "\n")
            f.flush()
            ok = "?" if rec["verdict"] is None else ("right" if (rec["verdict"] == "malicious") == rec["truth"] else "WRONG")
            print(f"{rec['case_id']:22s} {rec['condition']:13s} truth={'ATTACK' if rec['truth'] else 'normal'} "
                  f"-> {rec['verdict']} {rec['confidence']} [{ok}] {rec['prompt_tokens']}+{rec['output_tokens']} tok", flush=True)


if __name__ == "__main__":
    main()
