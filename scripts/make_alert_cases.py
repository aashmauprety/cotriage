"""Triage input: turn Suricata alarms into alert cases, the unit an analyst triages.

Suricata fires once per network event (nikto alone: ~6,300 alarms in 15 s), so
alarms are grouped as a SOC would: same host, signature, source and destination IP,
and less than GAP_MINUTES between consecutive alarms -> one case.

Ground truth comes only from the official AIT-LDS labels of suricata/fast.log:
an alarm is attack-related when EITHER label column is non-zero. For Suricata the
time column is needed: the nikto "non-compliant character" alarms and the root
reverse-shell "id check returned root" alarms carry only a time label. (Checked:
every labeled alarm involves the attacker's IP except one; the attacker's IP is
shared with a normal user, so the IP alone cannot decide.)
A case is malicious if any of its alarms is attack-related; mixed cases are counted.

Usage: python3 scripts/make_alert_cases.py  ->  alerts/cases.jsonl
"""
import json
import os
import re
from collections import Counter
from datetime import timedelta

import extract_windows as ew

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
GAP_MINUTES = 10
FAST = re.compile(r"\[\*\*\] \[(\d+):(\d+):\d+\] (.*?) \[\*\*\] \[Classification: (.*?)\] "
                  r"\[Priority: (\d+)\] \{(\w+)\} ([\d.]+):(\d+) -> ([\d.]+):(\d+)")


def alarms(host):
    out = []
    for n, ts, text, t_lab, l_lab in ew.load(host, "suricata/fast.log"):
        m = FAST.search(text)
        if not (ts and m):
            continue
        out.append({
            "ts": ts, "line_no": n, "sid": m.group(2), "signature": m.group(3),
            "classification": m.group(4), "priority": int(m.group(5)), "proto": m.group(6),
            "src_ip": m.group(7), "src_port": m.group(8), "dst_ip": m.group(9), "dst_port": m.group(10),
            "attack": t_lab != "0" or l_lab != "0",
            "label": l_lab if l_lab != "0" else (t_lab if t_lab != "0" else None),
            "text": text,
        })
    return out


def group(host, rows):
    cases, open_case = [], {}
    gap = timedelta(minutes=GAP_MINUTES)
    for a in sorted(rows, key=lambda r: r["ts"]):
        key = (a["sid"], a["src_ip"], a["dst_ip"])
        c = open_case.get(key)
        if c is None or a["ts"] - c["alarms"][-1]["ts"] > gap:
            c = {"host": host, "key": key, "alarms": []}
            open_case[key] = c
            cases.append(c)
        c["alarms"].append(a)
    return cases


def summarize(i, c):
    al = c["alarms"]
    first = al[0]
    n_att = sum(a["attack"] for a in al)
    return {
        "case_id": f"{c['host'].split('.')[1]}_{i:04d}",
        "host": c["host"],
        "start": al[0]["ts"].isoformat(), "end": al[-1]["ts"].isoformat(),
        "signature": first["signature"], "sid": first["sid"],
        "classification": first["classification"], "priority": first["priority"],
        "src_ip": first["src_ip"], "dst_ip": first["dst_ip"],
        "dst_ports": sorted({a["dst_port"] for a in al}, key=int)[:10],
        "n_alarms": len(al),
        # what the analyst sees: the alarm count plus up to 5 raw example alarms
        "examples": [a["text"] for a in (al if len(al) <= 5 else al[:3] + al[-2:])],
        # ground truth (official AIT-LDS labels), never shown to the LLM
        "truth": n_att > 0,
        "n_attack_alarms": n_att,
        "mixed": 0 < n_att < len(al),
        "labels": sorted({a["label"] for a in al if a["label"]}),
    }


def main():
    os.makedirs(os.path.join(BASE, "alerts"), exist_ok=True)
    out = os.path.join(BASE, "alerts", "cases.jsonl")
    total = Counter()
    with open(out, "w") as f:
        for host in ew.HOSTS:
            rows = alarms(host)
            cases = [summarize(i, c) for i, c in enumerate(group(host, rows))]
            for c in cases:
                f.write(json.dumps(c) + "\n")
            mal = sum(c["truth"] for c in cases)
            mixed = sum(c["mixed"] for c in cases)
            total.update(alarms=len(rows), cases=len(cases), malicious=mal, mixed=mixed)
            print(f"{host:16s} {len(rows):5d} alarms -> {len(cases):4d} cases "
                  f"({mal} malicious, {len(cases) - mal} benign, {mixed} mixed)")
    print(f"total: {dict(total)} -> {os.path.relpath(out, BASE)}")


if __name__ == "__main__":
    main()
