"""Alert triage: the LLM decides whether a Suricata alert case is a real attack,
with no tools (baseline) or with evidence from a set of tools.

The case is judged as a SIEM would show it once complete (alarm count included);
every tool looks only at data up to the end of the case.

  .venv/bin/python scripts/triage.py --preview cup_0165 --tools       # print a prompt, no LLM call
  .venv/bin/python scripts/triage.py --cases cup_0165 cup_0135       # run all conditions
  .venv/bin/python scripts/triage.py --case-file alerts/sample_claude.txt
  python3 scripts/triage.py --model qwen2.5:14b --all                 # local model, every case
Output: outputs/triage_<model>[_run<N>].jsonl (appends; finished case/condition pairs are skipped)
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tools  # noqa: E402

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
VERTEX_PROJECT = os.environ.get("VERTEX_PROJECT", "your-gcp-project")
# tools for alert triage, cheapest first ("baseline" is for log-line alerts, not cases)
LADDER = ["alert_history", "suricata", "ip_history", "audit_exec"]
# condition name -> tools given; L0..L4 climb the ladder, the rest are single tools
CONDITIONS = {
    "L0_none": [],
    "L1_history": LADDER[:1],
    "L2_+suricata": LADDER[:2],
    "L3_+ip": LADDER[:3],
    "L4_+audit": LADDER[:4],
    "only_suricata": ["suricata"],
    "only_ip": ["ip_history"],
    "only_audit": ["audit_exec"],
}

SYSTEM = """You are a security analyst triaging alerts from the network intrusion \
detection system (Suricata) of a Linux mail server (Apache webmail, Exim mail, \
Dovecot IMAP). Most alerts are false positives caused by normal user activity. \
Decide whether this alert case is a real attack. Use the additional evidence if any \
is given."""

TASK = """Alert case on host {host}
Signature:      {signature} (sid {sid})
Classification: {classification}, priority {priority}
Source -> dest: {src_ip} -> {dst_ip}  (dest ports: {ports})
Alarms in case: {n_alarms}, from {start} to {end}
Example alarms:
{examples}

{evidence}

Return JSON only, in this form:
{{"verdict": "malicious" or "benign",
  "attack_type": "<short name, e.g. port scan, web vulnerability scan, user enumeration, \
password brute force, webshell upload, command execution, privilege escalation, none>",
  "confidence": <0.0-1.0, how sure you are that it is malicious>,
  "reason": "<one sentence>"}}"""


def load_cases():
    return {c["case_id"]: c for c in map(json.loads, open(os.path.join(BASE, "alerts", "cases.jsonl")))}


_server_ips = None


def server_ip(host):
    """The monitored server's own address: the most common alarm destination."""
    global _server_ips
    if _server_ips is None:
        from collections import Counter
        counts = {}
        for c in load_cases().values():
            counts.setdefault(c["host"], Counter())[c["dst_ip"]] += c["n_alarms"]
        _server_ips = {h: c.most_common(1)[0][0] for h, c in counts.items()}
    return _server_ips[host]


def tool_input(case):
    """The tools take an alert as host / time span / text lines. They investigate the
    remote party: usually the source, but the destination for alarms on traffic the
    server sends out (e.g. "id check returned root" goes server -> attacker)."""
    remote = case["dst_ip"] if case["src_ip"] == server_ip(case["host"]) else case["src_ip"]
    return {"host": case["host"], "start": case["start"], "end": case["end"],
            "lines": [f"(alert) {remote} {case['signature']}"],
            "signature": case["signature"], "src_ip": case["src_ip"], "n_alarms": case["n_alarms"]}


def is_hard(case):
    """Policy/protocol alarms fire for normal users too; their name gives no verdict."""
    return case["signature"].startswith("ET POLICY") or "generic error" in case["signature"]


def evidence(case, tool_names, cache=None):
    """Tool outputs are computed once per case and reused across conditions."""
    if not tool_names:
        return "No additional evidence is available.", 0.0
    cache = {} if cache is None else cache
    parts, secs = [], 0.0
    for t in tool_names:
        if t not in cache:
            t0 = time.time()
            cache[t] = (tools.TOOLS[t](tool_input(case)), time.time() - t0)
        parts.append(f"Evidence from tool '{t}':\n{cache[t][0]}")
        secs += cache[t][1]
    return "Additional evidence:\n\n" + "\n\n".join(parts), secs


def build_prompt(case, tool_names, cache=None):
    return TASK.format(
        host=case["host"], signature=case["signature"], sid=case["sid"],
        classification=case["classification"], priority=case["priority"],
        src_ip=case["src_ip"], dst_ip=case["dst_ip"], ports=", ".join(case["dst_ports"]),
        n_alarms=case["n_alarms"], start=case["start"], end=case["end"],
        examples="\n".join("  " + e[:220] for e in case["examples"]),
        evidence=evidence(case, tool_names, cache)[0])


_claude = None


def ask(model, prompt, effort, system=SYSTEM):
    """Returns (reply text, stop reason, input tokens, output tokens)."""
    global _claude
    if model.startswith("claude-"):
        if _claude is None:
            from anthropic import AnthropicVertex
            _claude = AnthropicVertex(region="global", project_id=VERTEX_PROJECT)
        # structured outputs are blocked by the org policy, so JSON comes from the prompt;
        # Haiku 4.5 does not accept the effort setting (Haiku 5.5 does)
        extra = {} if model.startswith("claude-haiku-4") else {"output_config": {"effort": effort}}
        r = _claude.messages.create(
            model=model, max_tokens=8000, system=system,
            messages=[{"role": "user", "content": prompt}], **extra,
        )
        text = next((b.text for b in r.content if b.type == "text"), "")
        return text, r.stop_reason, r.usage.input_tokens, r.usage.output_tokens
    if model.startswith("gemini-"):
        return _ask_gemini(model, prompt, system)
    if "/" in model:  # open models on Vertex AI (e.g. openai/gpt-oss-120b-maas)
        return _ask_maas(model, prompt, system, effort)
    body = json.dumps({"model": model, "stream": False, "format": "json",
                       "messages": [{"role": "system", "content": system},
                                    {"role": "user", "content": prompt}],
                       "options": {"temperature": 0, "num_ctx": 16384}}).encode()
    req = urllib.request.Request("http://localhost:11434/api/chat", body,
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=1800) as resp:
        r = json.load(resp)
    return r["message"]["content"], r.get("done_reason"), r.get("prompt_eval_count"), r.get("eval_count")


_gcred = None
_glock = __import__("threading").Lock()


def _ask_gemini(model, prompt, system):
    """Gemini on Vertex AI (REST, default thinking). Output tokens include the thinking tokens,
    which are billed as output."""
    global _gcred
    import google.auth
    import google.auth.transport.requests
    import requests
    with _glock:
        if _gcred is None:
            _gcred, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    url = (f"https://aiplatform.googleapis.com/v1/projects/{VERTEX_PROJECT}/locations/global/"
           f"publishers/google/models/{model}:generateContent")
    body = {"systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 8000}}
    for attempt in range(8):
        with _glock:
            if not _gcred.valid or not _gcred.token:
                _gcred.refresh(google.auth.transport.requests.Request())
            token = _gcred.token
        r = requests.post(url, headers={"Authorization": "Bearer " + token}, json=body, timeout=600)
        if r.status_code == 401 and attempt < 7:  # token rejected: force a refresh
            with _glock:
                _gcred.refresh(google.auth.transport.requests.Request())
            continue
        if r.status_code in (429, 500, 503) and attempt < 7:
            time.sleep(2 ** attempt)
            continue
        r.raise_for_status()
        break
    j = r.json()
    c = (j.get("candidates") or [{}])[0]
    text = "".join(p.get("text", "") for p in c.get("content", {}).get("parts", []) if not p.get("thought"))
    u = j.get("usageMetadata", {})
    return text, c.get("finishReason"), u.get("promptTokenCount", 0), u.get("candidatesTokenCount", 0) + u.get("thoughtsTokenCount", 0)


def _ask_maas(model, prompt, system, effort):
    """Open-weight models served by Vertex AI through its OpenAI-compatible endpoint.
    Output tokens include the reasoning tokens (billed as output)."""
    global _gcred
    import google.auth
    import google.auth.transport.requests
    import requests
    with _glock:
        if _gcred is None:
            _gcred, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    # the global endpoint stalls for gpt-oss (Nov 2026); us-central1 answers reliably
    url = (f"https://us-central1-aiplatform.googleapis.com/v1/projects/{VERTEX_PROJECT}/locations/us-central1/"
           "endpoints/openapi/chat/completions")
    body = {"model": model, "max_tokens": 8000, "reasoning_effort": effort,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
    for attempt in range(8):
        with _glock:
            if not _gcred.valid or not _gcred.token:
                _gcred.refresh(google.auth.transport.requests.Request())
            token = _gcred.token
        try:
            r = requests.post(url, headers={"Authorization": "Bearer " + token}, json=body, timeout=90)
        except requests.exceptions.RequestException:
            if attempt == 7:
                raise
            time.sleep(2 ** attempt)
            continue
        if r.status_code == 401 and attempt < 7:  # token rejected: force a refresh
            with _glock:
                _gcred.refresh(google.auth.transport.requests.Request())
            continue
        if r.status_code in (429, 500, 502, 503) and attempt < 7:
            time.sleep(2 ** attempt)
            continue
        r.raise_for_status()
        break
    j = r.json()
    c = j["choices"][0]
    u = j.get("usage", {})
    return c["message"].get("content") or "", c.get("finish_reason"), u.get("prompt_tokens", 0), u.get("completion_tokens", 0)


_VERDICT = __import__("re").compile(r'"verdict"\s*:\s*"(malicious|benign)"')


def parse_verdict(text):
    """JSON verdict; if the JSON is broken (e.g. gpt-oss writes "confidence": 0. nine),
    fall back to the verdict field alone (confidence and reason then stay empty)."""
    text = text or ""
    start, end = text.find("{"), text.rfind("}")
    try:
        v = json.loads(text[start:end + 1]) if 0 <= start < end else None
    except json.JSONDecodeError:
        v = None
    if v is not None and v.get("verdict") in ("malicious", "benign"):
        return v
    m = _VERDICT.search(text)
    return {"verdict": m.group(1)} if m else None


def run_one(case, condition, cache, args):
    names = CONDITIONS[condition]
    ev, tool_secs = evidence(case, names, cache)
    prompt = build_prompt(case, names, cache)
    t0 = time.time()
    text, stop, tin, tout = ask(args.model, prompt, args.effort)
    v = parse_verdict(text)
    return {
        "case_id": case["case_id"], "condition": condition, "tools": names, "model": args.model,
        "truth": case["truth"], "hard": is_hard(case), "mixed": case["mixed"],
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
    ap.add_argument("--preview", help="print the prompt for this case_id and exit")
    ap.add_argument("--tools", nargs="*", help="with --preview: tool names; bare --tools = whole ladder")
    ap.add_argument("--cases", nargs="*", help="case_ids to run")
    ap.add_argument("--case-file", help="file with one case_id per line")
    ap.add_argument("--all", action="store_true", help="run every case")
    ap.add_argument("--model", default="claude-opus-5-5")
    ap.add_argument("--effort", default="medium", help="Claude effort level")
    ap.add_argument("--conditions", nargs="*", default=list(CONDITIONS))
    ap.add_argument("--workers", type=int, default=4, help="parallel requests (Claude only)")
    ap.add_argument("--run", type=int, default=1, help="repeat number; runs > 1 get their own output file")
    args = ap.parse_args()
    cases = load_cases()

    if args.preview:
        case = cases[args.preview]
        names = [] if args.tools is None else (args.tools or LADDER)
        print("=== SYSTEM ===\n" + SYSTEM + "\n\n=== USER ===\n" + build_prompt(case, names))
        print(f"\n=== GROUND TRUTH (hidden from the LLM) === malicious={case['truth']} labels={case['labels']}")
        return

    if args.all:
        ids = list(cases)
    elif args.case_file:
        ids = [l.strip() for l in open(args.case_file) if l.strip()]
    else:
        ids = args.cases or []
    suffix = "" if args.run == 1 else f"_run{args.run}"
    out_path = os.path.join(BASE, "outputs", f"triage_{args.model.replace(':', '_').replace('/', '_')}{suffix}.jsonl")
    done = set()
    if os.path.exists(out_path):
        done = {(r["case_id"], r["condition"]) for r in map(json.loads, open(out_path))}

    jobs = []
    for cid in ids:
        cache = {}
        for cond in args.conditions:
            if (cid, cond) not in done:
                evidence(cases[cid], CONDITIONS[cond], cache)  # run tools up front, sequentially
                jobs.append((cases[cid], cond, cache))
    print(f"{len(ids)} cases, {len(jobs)} calls to make -> {os.path.relpath(out_path, BASE)}", flush=True)

    workers = args.workers if args.model.startswith("claude-") else 1
    with open(out_path, "a") as f, ThreadPoolExecutor(workers) as pool:
        for rec in pool.map(lambda j: run_one(*j, args), jobs):
            f.write(json.dumps(rec) + "\n")
            f.flush()
            ok = "?" if rec["verdict"] is None else (
                "right" if (rec["verdict"] == "malicious") == rec["truth"] else "WRONG")
            print(f"{rec['case_id']:12s} {rec['condition']:14s} truth={'ATTACK' if rec['truth'] else 'normal'} "
                  f"-> {rec['verdict']} {rec['confidence']} [{ok}]  "
                  f"{rec['prompt_tokens']}+{rec['output_tokens']} tok  stop={rec['stop_reason']}", flush=True)


if __name__ == "__main__":
    main()
