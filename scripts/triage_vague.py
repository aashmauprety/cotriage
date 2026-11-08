"""Setting B: investigate vague "Suspicious behaviour" alerts (cf. Eilertsen et al.)
with a ladder of tools. The alert carries no IP or signature, so the ladder starts
with an overview of the window; ip_history then follows the busiest remote IPs.

  .venv/bin/python scripts/triage_vague.py --preview cup_v10 --tools
  .venv/bin/python scripts/triage_vague.py --model claude-haiku-5-5 --all --window 5
Output: outputs/vague<window>_<model>[_run<N>].jsonl
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tools  # noqa: E402
from triage import ask, parse_verdict, server_ip  # noqa: E402

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LADDER = ["overview", "suricata", "ip_history", "audit_exec"]
CONDITIONS = {
    "V0_none": [],
    "V1_overview": LADDER[:1],
    "V2_+suricata": LADDER[:2],
    "V3_+ip": LADDER[:3],
    "V4_+audit": LADDER[:4],
    "only_ip": ["ip_history"],
    "only_audit": ["audit_exec"],
}

SYSTEM = """You are a security analyst investigating an alert on a Linux mail server \
(Apache webmail, Exim mail, Dovecot IMAP). Most alerts are false positives caused by \
normal user activity. Decide whether the host was under attack during the alert window. \
Use the additional evidence if any is given."""

TASK = """Alert on host {host} at {end}
Source: machine-learning-based intrusion detection system
Message: "Suspicious behaviour"
No further context is provided by the detector. The investigation window is
{start} to {end} (the {minutes} minutes before the alert).

{evidence}

Return JSON only, in this form:
{{"verdict": "malicious" or "benign",
  "attack_type": "<short name, e.g. port scan, web vulnerability scan, user enumeration, \
password brute force, webshell upload, command execution, privilege escalation, none>",
  "confidence": <0.0-1.0, how sure you are that it is malicious>,
  "reason": "<one sentence>"}}"""


def load_alerts(window):
    path = os.path.join(BASE, "alerts", f"vague_{window}.jsonl")
    return {a["alert_id"]: a for a in map(json.loads, open(path))}


def tool_input(alert):
    """ip_history needs addresses: give it the busiest remote IPs of the window."""
    ips = tools.top_external_ips(alert, server_ip(alert["host"]))
    return {"host": alert["host"], "start": alert["start"], "end": alert["end"],
            "lines": [f"(alert) {ip}" for ip in ips]}


def evidence(alert, names, cache):
    if not names:
        return "No additional evidence is available.", 0.0
    parts, secs = [], 0.0
    for t in names:
        if t not in cache:
            t0 = time.time()
            cache[t] = (tools.TOOLS[t](tool_input(alert)), time.time() - t0)
        parts.append(f"Evidence from tool '{t}':\n{cache[t][0]}")
        secs += cache[t][1]
    return "Additional evidence:\n\n" + "\n\n".join(parts), secs


def build_prompt(alert, names, cache):
    minutes = int((tools.datetime.fromisoformat(alert["end"]) -
                   tools.datetime.fromisoformat(alert["start"])).total_seconds() // 60)
    return TASK.format(host=alert["host"], start=alert["start"], end=alert["end"],
                       minutes=minutes, evidence=evidence(alert, names, cache)[0])


def run_one(alert, condition, cache, args):
    names = CONDITIONS[condition]
    ev, tool_secs = evidence(alert, names, cache)
    t0 = time.time()
    text, stop, tin, tout = ask(args.model, build_prompt(alert, names, cache), args.effort, SYSTEM)
    v = parse_verdict(text)
    return {
        "case_id": alert["alert_id"], "condition": condition, "tools": names, "model": args.model,
        "truth": alert["truth"], "hard": alert["anchor_phase"] in ("webshell", "mail-curl", "upload"),
        "mixed": False, "anchor_phase": alert["anchor_phase"],
        "verdict": v["verdict"] if v else None,
        "confidence": float(v["confidence"]) if v and isinstance(v.get("confidence"), (int, float)) else None,
        "attack_type": v.get("attack_type") if v else None,
        "reason": v.get("reason") if v else None,
        "evidence_chars": len(ev), "tool_seconds": round(tool_secs, 2),
        "prompt_tokens": tin, "output_tokens": tout,
        "llm_seconds": round(time.time() - t0, 1), "stop_reason": stop, "raw": text,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preview", help="print the prompt for this alert_id and exit")
    ap.add_argument("--tools", nargs="*", help="with --preview: tool names; bare --tools = whole ladder")
    ap.add_argument("--alerts", nargs="*")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--effort", default="medium")
    ap.add_argument("--conditions", nargs="*", default=list(CONDITIONS))
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--window", type=int, default=30, help="which alert set: alerts/vague_<window>.jsonl")
    args = ap.parse_args()
    alerts = load_alerts(args.window)

    if args.preview:
        a = alerts[args.preview]
        names = [] if args.tools is None else (args.tools or LADDER)
        print("=== SYSTEM ===\n" + SYSTEM + "\n\n=== USER ===\n" + build_prompt(a, names, {}))
        print(f"\n=== GROUND TRUTH (hidden from the LLM) === malicious={a['truth']} "
              f"phases in window={a['phases_in_window']}")
        return

    ids = list(alerts) if args.all else (args.alerts or [])
    suffix = "" if args.run == 1 else f"_run{args.run}"
    out_path = os.path.join(BASE, "outputs", f"vague{args.window}_{args.model.replace(':', '_').replace('/', '_')}{suffix}.jsonl")
    done = set()
    if os.path.exists(out_path):
        done = {(r["case_id"], r["condition"]) for r in map(json.loads, open(out_path))}
    jobs = []
    for aid in ids:
        cache = {}
        for cond in args.conditions:
            if (aid, cond) not in done:
                evidence(alerts[aid], CONDITIONS[cond], cache)
                jobs.append((alerts[aid], cond, cache))
    print(f"{len(ids)} alerts, {len(jobs)} calls to make -> {os.path.relpath(out_path, BASE)}", flush=True)
    workers = args.workers if args.model.startswith("claude-") else 1
    with open(out_path, "a") as f, ThreadPoolExecutor(workers) as pool:
        for rec in pool.map(lambda j: run_one(*j, args), jobs):
            f.write(json.dumps(rec) + "\n")
            f.flush()
            ok = "?" if rec["verdict"] is None else (
                "right" if (rec["verdict"] == "malicious") == rec["truth"] else "WRONG")
            print(f"{rec['case_id']:11s} {rec['condition']:13s} truth={'ATTACK' if rec['truth'] else 'normal'} "
                  f"-> {rec['verdict']} {rec['confidence']} [{ok}]", flush=True)


if __name__ == "__main__":
    main()
