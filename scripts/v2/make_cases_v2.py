"""Aggregate labeled AIT-ADS alerts (alerts_v2/<scenario>.jsonl) into alert cases, as in Setting A.

Duplicates are dropped: the same log line written to several files (syslog, mail.log, mail.info), and
Suricata alarms that appear both in eve.json and (as Wazuh 'IDS event') in fast.log.
Key = (rule description, host, source address); a new case starts after a gap > 10 min
or when the open case is older than one hour.
Writes alerts_v2/cases_<scenario>.jsonl and prints counts.

Usage: python3 -I scripts/v2/make_cases_v2.py <scenario> [<scenario> ...]
"""
import collections
import json
import os
import sys

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
GAP = 600
MAX_SPAN = 3600  # a case is closed after one hour, so long-running attacks yield a series of cases


def main():
    for scen in sys.argv[1:]:
        seen, open_cases, cases = set(), {}, []
        for l in open(os.path.join(BASE, "alerts_v2", f"{scen}.jsonl")):
            a = json.loads(l)
            if a["location"] and a["location"].endswith("fast.log"):
                continue  # the same Suricata alarm is also in eve.json
            dup = (a["rule"], a["full_log"], int(a["t"])) if a["full_log"] else None
            if dup:
                if dup in seen:
                    continue
                seen.add(dup)
            host = a["host"] or a["agent_ip"]
            key = (a["desc"], host, a["src"])
            c = open_cases.get(key)
            if c is None or a["t"] - c["end"] > GAP or a["t"] - c["start"] > MAX_SPAN:
                c = {"case_id": f"{scen}_{len(cases):05d}", "scenario": scen, "desc": a["desc"], "rule": a["rule"],
                     "level": a["level"], "host": host, "src": a["src"], "dst": a["dst"], "start": a["t"], "end": a["t"],
                     "n_alerts": 0, "n_mal": 0, "labels": collections.Counter(), "why": collections.Counter(), "examples": []}
                cases.append(c)
                open_cases[key] = c
            c["end"] = a["t"]
            c["n_alerts"] += 1
            c["n_mal"] += a["truth"]
            c["labels"].update(a["labels"])
            if a["why"]:
                c["why"][a["why"]] += 1
            if a.get("uncertain"):
                c["why"]["uncertain"] += 1
            ex = a["full_log"] or a.get("eve")  # Suricata eve alarms have no log line: show the alarm's fields
            if len(c["examples"]) < 3 and ex:
                c["examples"].append(ex)
        with open(os.path.join(BASE, "alerts_v2", f"cases_{scen}.jsonl"), "w") as f:
            for c in cases:
                c["truth"] = c["n_mal"] > 0
                c["mixed"] = 0 < c["n_mal"] < c["n_alerts"]
                c["labels"] = dict(c["labels"])
                c["why"] = dict(c["why"])
                # uncertain = benign by the labels but involving the shared VPN gateway address during an
                # attack phase: such cases are excluded from evaluation
                c["certain"] = c["truth"] or not c["why"].get("uncertain")
                f.write(json.dumps(c) + "\n")
        mal = [c for c in cases if c["truth"]]
        print(f"{scen}: {len(cases)} cases ({len(mal)} malicious, {sum(c['mixed'] for c in cases)} mixed) "
              f"from {sum(c['n_alerts'] for c in cases)} deduplicated alerts")
        byd = collections.Counter((c["desc"][:60], c["truth"]) for c in cases)
        sigs = {d for d, _ in byd}
        amb = [(d, byd[(d, True)], byd[(d, False)]) for d in sigs if byd[(d, True)] and byd[(d, False)]]
        print("  ambiguous signatures (malicious / benign cases):")
        for d, m, b in sorted(amb, key=lambda x: -x[1]):
            print(f"    {m:4d} / {b:5d}  {d}")
        only = sorted(((d, byd[(d, True)]) for d in sigs if byd[(d, True)] and not byd[(d, False)]), key=lambda x: -x[1])
        print("  attack-only signatures:", ", ".join(f"{d} ({m})" for d, m in only[:12]))


if __name__ == "__main__":
    main()
