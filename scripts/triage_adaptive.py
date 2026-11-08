"""Adaptive triage: the LLM decides per alert which tools to call, knowing their cost.

Each turn the model answers with one JSON action:
  {"action": "call_tool", "tool": "<name>"}                      -> we run the tool, return its output
  {"action": "verdict", "verdict": ..., "attack_type": ..., "confidence": ..., "reason": ...}
At most MAX_CALLS tools; after that the model must give a verdict. The cost of an alert
is the sum over all turns (each turn re-sends the conversation so far).
A reply without a readable action gets one reminder of the format (its cost counted);
if it is still unreadable, or on a refusal, the alert ends as "malicious" (escalated),
as in the fixed configurations.

  .venv/bin/python scripts/triage_adaptive.py --model claude-haiku-5-5 --cases cup_0165 cup_0135
  .venv/bin/python scripts/triage_adaptive.py --model claude-haiku-5-5 --case-file alerts/sample_claude.txt --run 2
  .venv/bin/python scripts/triage_adaptive.py --setting B30 --model claude-haiku-5-5 --all
Output: outputs/adaptive_<setting>_<model>[_run<N>].jsonl
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tools  # noqa: E402
import triage  # noqa: E402
import triage_vague  # noqa: E402

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MAX_CALLS = 4

# what the model is told about each tool; cost = relative price of calling it
# (output size and the size of the data store the tool must search)
TOOL_MENU = {
    "A": [("alert_history", 1, "how often this alarm fires per day on this host, overall and from this source"),
          ("suricata", 1, "other Suricata alarms on this host around the alert"),
          ("ip_history", 5, "everything the remote IP did in the last 30 minutes (web requests, user agents, "
                            "logins) and its activity on previous days"),
          ("audit_exec", 10, "commands executed on the server around the alert, from the kernel audit log")],
    "B": [("overview", 1, "summary of the window: log volumes, busiest clients, status codes, user agents, "
                          "failed logins, Suricata alarms"),
          ("suricata", 1, "Suricata alarms on this host around the alert"),
          ("ip_history", 5, "everything the busiest remote IPs did in the window and on previous days"),
          ("audit_exec", 10, "commands executed on the server around the alert, from the kernel audit log")],
}

PROTOCOL = """You may call investigation tools before deciding. Each tool has a cost; \
call a tool only when its evidence is likely to change or confirm your decision, and \
decide as soon as you are confident. You can call at most {max_calls} tools.

Available tools (cost in units):
{menu}

Reply with exactly one JSON object and nothing else, either
{{"action": "call_tool", "tool": "<tool name>"}}
or
{{"action": "verdict", "verdict": "malicious" or "benign",
  "attack_type": "<short name or none>",
  "confidence": <0.0-1.0, how sure you are that it is malicious>,
  "reason": "<one sentence>"}}"""


def alert_text(setting, item):
    """The alert as in the fixed-configuration prompts, without the evidence block
    and without their answer-format instructions."""
    if setting == "A":
        body = triage.build_prompt(item, [], {})
    else:
        body = triage_vague.build_prompt(item, [], {})
    return body.split("\n\nNo additional evidence is available.")[0]


def tool_input(setting, item):
    return triage.tool_input(item) if setting == "A" else triage_vague.tool_input(item)


def parse_action(text):
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        a = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return a if isinstance(a, dict) and a.get("action") in ("call_tool", "verdict") else None


_client = None


def chat(model, system, messages, effort):
    global _client
    if _client is None:
        from anthropic import AnthropicVertex
        _client = AnthropicVertex(region="global", project_id=triage.VERTEX_PROJECT)
    extra = {} if model.startswith("claude-haiku-4") else {"output_config": {"effort": effort}}
    r = _client.messages.create(model=model, max_tokens=8000, system=system, messages=messages, **extra)
    text = next((b.text for b in r.content if b.type == "text"), "")
    return text, r.stop_reason, r.usage.input_tokens, r.usage.output_tokens


def run_one(setting, item, args):
    menu = TOOL_MENU[setting]
    names = {n for n, _, _ in menu}
    system = (triage.SYSTEM if setting == "A" else triage_vague.SYSTEM) + "\n\n" + PROTOCOL.format(
        max_calls=MAX_CALLS, menu="\n".join(f"- {n} (cost {c}): {d}" for n, c, d in menu))
    messages = [{"role": "user", "content": alert_text(setting, item)}]
    called, turns, tin, tout, tool_secs, verdict, stop = [], [], 0, 0, 0.0, None, None
    retried = False
    t0 = time.time()
    while True:
        text, stop, i, o = chat(args.model, system, messages, args.effort)
        tin, tout = tin + i, tout + o
        action = parse_action(text)
        turns.append(text)
        if action is None and stop != "refusal" and not retried:
            # one reminder of the reply format (counted in the cost), then give up
            retried = True
            messages += [{"role": "assistant", "content": text or "(empty)"},
                         {"role": "user", "content": "Reply with exactly one JSON object as specified: "
                                                     "a call_tool action or a verdict."}]
            continue
        if action is None or stop == "refusal":
            break
        if action["action"] == "verdict" and action.get("verdict") in ("malicious", "benign"):
            verdict = action
            break
        tool = action.get("tool")
        messages.append({"role": "assistant", "content": text})
        if action["action"] != "call_tool" or tool not in names or tool in called:
            msg = "Invalid or repeated tool. Choose another tool or give your verdict."
        elif len(called) >= MAX_CALLS:
            msg = "Tool limit reached. Give your verdict now."
        else:
            s0 = time.time()
            out = tools.TOOLS[tool](tool_input(setting, item))
            tool_secs += time.time() - s0
            called.append(tool)
            msg = f"Output of tool '{tool}':\n{out}"
            if len(called) >= MAX_CALLS:
                msg += "\n\nTool limit reached. Give your verdict now."
        messages.append({"role": "user", "content": msg})
        if len(turns) > MAX_CALLS + 3:  # safety stop
            break
    cid = item.get("case_id") or item.get("alert_id")
    return {
        "case_id": cid, "setting": setting, "condition": "adaptive", "model": args.model,
        "truth": item["truth"], "tools_called": called, "n_turns": len(turns),
        "verdict": verdict["verdict"] if verdict else None,
        "confidence": float(verdict.get("confidence", 0)) if verdict else None,
        "attack_type": verdict.get("attack_type") if verdict else None,
        "reason": verdict.get("reason") if verdict else None,
        "prompt_tokens": tin, "output_tokens": tout, "tool_seconds": round(tool_secs, 2),
        "llm_seconds": round(time.time() - t0 - tool_secs, 1), "stop_reason": stop, "turns": turns,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--setting", choices=["A", "B30", "B5"], default="A")
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--effort", default="medium")
    ap.add_argument("--cases", nargs="*")
    ap.add_argument("--case-file")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--run", type=int, default=1)
    args = ap.parse_args()

    if args.setting == "A":
        items, kind = triage.load_cases(), "A"
    else:
        items, kind = triage_vague.load_alerts(int(args.setting[1:])), "B"
    ids = list(items) if args.all else (
        [l.strip() for l in open(args.case_file) if l.strip()] if args.case_file else args.cases or [])
    suffix = "" if args.run == 1 else f"_run{args.run}"
    out_path = os.path.join(BASE, "outputs", f"adaptive_{args.setting}_{args.model}{suffix}.jsonl")
    done = set()
    if os.path.exists(out_path):
        done = {r["case_id"] for r in map(json.loads, open(out_path))}
    todo = [items[i] for i in ids if i not in done]
    print(f"{len(todo)} alerts -> {os.path.relpath(out_path, BASE)}", flush=True)
    with open(out_path, "a") as f, ThreadPoolExecutor(args.workers) as pool:
        for rec in pool.map(lambda it: run_one(kind, it, args), todo):
            f.write(json.dumps(rec) + "\n")
            f.flush()
            ok = "?" if rec["verdict"] is None else (
                "right" if (rec["verdict"] == "malicious") == rec["truth"] else "WRONG")
            print(f"{rec['case_id']:12s} truth={'ATTACK' if rec['truth'] else 'normal'} tools={rec['tools_called']} "
                  f"-> {rec['verdict']} {rec['confidence']} [{ok}] {rec['prompt_tokens']}+{rec['output_tokens']} tok",
                  flush=True)


if __name__ == "__main__":
    main()
