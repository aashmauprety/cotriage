"""Label AIT-ADS alerts (Wazuh incl. Suricata) of one AIT-LDS v2 scenario with line-level ground truth.

An alert is malicious if
  (a) its full_log equals a log line that the AIT-LDS v2 labels mark as attack-related, or
  (b) it is a Suricata DNS alarm for a name that appears in a labeled dnsmasq query line
      (the DNS exfiltration runs during the whole data set, not only in its phase window), or
  (c) it falls into an attack phase and involves the attacker's own address (source, destination, or log text).
Each scenario has two attacker addresses in the labeled lines: the attacker's own host and the VPN gateway,
which all remote employees share. An address that also occurs in alerts outside the attack phases is shared;
alerts that involve only a shared address during a phase are marked uncertain and excluded from evaluation.
Attacker addresses = client addresses of labeled Apache/VPN lines.
Writes alerts_v2/<scenario>.jsonl (one compact record per alert) and prints a coverage report.

Usage: python3 -I scripts/v2/label_alerts.py <scenario>
"""
import collections
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def labeled_lines(scen):
    root = os.path.join(BASE, "AIT-LDS-v2", scen)
    text2labels, attacker_ips = {}, collections.Counter()
    for dp, _, fs in os.walk(os.path.join(root, "labels")):
        for f in fs:
            lab_path = os.path.join(dp, f)
            log_path = lab_path.replace(os.sep + "labels" + os.sep, os.sep + "gather" + os.sep, 1)
            if not os.path.exists(log_path):
                continue
            want = {}
            for l in open(lab_path):
                r = json.loads(l)
                want[r["line"]] = r["labels"]
            with open(log_path, errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    if i in want:
                        t = line.rstrip("\n")
                        text2labels[t] = want[i]
                        if "apache2" in log_path or "openvpn" in log_path:
                            m = IP.search(t)
                            if m:
                                attacker_ips[m.group(1)] += 1
    return text2labels, attacker_ips


def eve_detail(data):
    """One line with the fields a SIEM shows for a Suricata eve alarm (ports, protocol, DNS name, HTTP request, TLS SNI)."""
    if not data.get("alert"):
        return None
    parts = [f"{data.get('proto', '')} {data.get('src_ip')}:{data.get('src_port', '')} -> {data.get('dest_ip')}:{data.get('dest_port', '')}",
             f"app={data.get('app_proto', '-')}"]
    for q in ((data.get("dns") or {}).get("query") or [])[:1]:
        if isinstance(q, dict):
            n = q.get("rrname") or ""
            if len(n) > 100:  # keep both ends of long names (the prompt shows 220 characters per line)
                n = f"{n[:45]}...{n[-45:]} (name length {len(n)})"
            parts.append(f"dns query {q.get('rrtype', '')} {n}")
    h = data.get("http") or {}
    if h:
        parts.append(" ".join(str(x) for x in ("http", h.get("http_method"), h.get("hostname"), h.get("url"), h.get("status"))
                              if x) + (f' UA="{h["http_user_agent"]}"' if h.get("http_user_agent") else ""))
    tls = data.get("tls") or {}
    if tls:
        parts.append(f"tls {tls.get('version', '')}" + (f" sni={tls['sni']}" if tls.get("sni") else ""))
    return " ".join(parts)[:300]


def main():
    scen = sys.argv[1]
    phases = [(r["attack"], float(r["start"]), float(r["end"]))
              for r in csv.DictReader(open(os.path.join(BASE, "AIT-ADS", "labels.csv"))) if r["scenario"] == scen]
    text2labels, att = labeled_lines(scen)
    dns_names = {}
    for t, labs in text2labels.items():
        m = re.search(r"query\[\w+\] (\S+) from", t)
        if m:
            dns_names[m.group(1)] = labs
    # a few labeled names (e.g. the company's own mail server, hit by the attacker's DNS scan) are also queried by
    # normal users (>= 10 unlabeled queries, more than labeled ones); for those, a DNS alarm counts only if it comes from the labeled query's client within a minute
    normal_q, labeled_q = collections.Counter(), collections.Counter()
    for dp, _, fs in os.walk(os.path.join(BASE, "AIT-LDS-v2", scen, "gather")):
        for f in fs:
            if f.startswith("dnsmasq.log"):
                for t in open(os.path.join(dp, f), errors="replace"):
                    m = re.search(r"query\[\w+\] (\S+) from (\S+)", t)
                    if m and m.group(1) in dns_names:
                        (labeled_q if t.rstrip("\n") in text2labels else normal_q)[m.group(1)] += 1
    shared_names = {n: [] for n in normal_q if normal_q[n] >= 10 and normal_q[n] > labeled_q[n]}
    for t in text2labels:
        m = re.search(r"query\[\w+\] (\S+) from (\S+)", t)
        if m and m.group(1) in shared_names:
            ts = datetime.strptime(f"2022 {t[:15]}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
            shared_names[m.group(1)].append((m.group(2), ts))
    print("labeled DNS names", len(dns_names), "also queried by normal users", sorted(shared_names))
    attackers = {ip for ip, n in att.items() if n >= 3}
    outside = collections.Counter()
    for line in open(os.path.join(BASE, "AIT-ADS", "extracted", f"{scen}_wazuh.json")):
        if not any(ip in line for ip in attackers):
            continue
        r = json.loads(line)
        ts = datetime.fromisoformat(r["@timestamp"].replace("Z", "+00:00")).timestamp()
        if not any(s <= ts <= e for _, s, e in phases):
            outside.update(ip for ip in attackers if ip in line)
    shared = {ip for ip in attackers if outside[ip]}
    own = attackers - shared
    print("attacker's own addresses", sorted(own), "shared (VPN gateway)", sorted(shared))
    print("labeled lines", len(text2labels), "attacker IPs", att.most_common(5))
    out = open(os.path.join(BASE, "alerts_v2", f"{scen}.jsonl"), "w")
    stats = collections.Counter()
    for line in open(os.path.join(BASE, "AIT-ADS", "extracted", f"{scen}_wazuh.json")):
        r = json.loads(line)
        ts = datetime.fromisoformat(r["@timestamp"].replace("Z", "+00:00")).timestamp()
        phase = next((a for a, s, e in phases if s <= ts <= e), None)
        rule = r["rule"]
        data = r.get("data") or {}
        sur = "suricata" in rule.get("groups", [])
        sig = (data.get("alert") or {}).get("signature") if sur else None
        full = r.get("full_log")
        if sur and not sig and full:  # fast.log variant
            m = re.search(r"\] (.*?) \[\*\*\]", full)
            sig = m.group(1) if m else rule["description"]
        src = data.get("src_ip") or data.get("srcip")
        dst = data.get("dest_ip") or (data.get("dstip") or "").split(":")[0] or None
        labels = text2labels.get(full) if full else None
        why = "line" if labels else None
        rr = [q.get("rrname") for q in ((data.get("dns") or {}).get("query") or []) if isinstance(q, dict)]
        hit = [n for n in rr if n in dns_names and (n not in shared_names or any(
            ip == src and abs(t - ts) <= 60 for ip, t in shared_names[n]))]
        if not labels and hit:
            labels, why = dns_names[hit[0]], "dns_line"
        involved = {ip for ip in attackers if ip in (src, dst) or ip in (full or "")} if phase else set()
        uncertain = False
        if not labels and involved & own:
            labels, why = [phase], "attacker_ip_in_phase"
        elif not labels and involved:
            uncertain = True
        rec = {"t": ts, "rule": rule["id"], "level": rule["level"],
               "desc": f"Suricata: {sig}" if sur else rule["description"],
               "groups": rule.get("groups", []), "host": (r.get("predecoder") or {}).get("hostname"),
               "agent_ip": r["agent"].get("ip"), "location": r.get("location"),
               "src": src, "dst": dst, "user": data.get("srcuser") or data.get("dstuser"),
               "full_log": full[:400] if full else None, "eve": eve_detail(data) if sur and not full else None,
               "phase": phase, "truth": bool(labels), "labels": labels or [], "why": why, "uncertain": uncertain}
        out.write(json.dumps(rec) + "\n")
        stats[("in_phase" if phase else "out_phase", "mal" if labels else "uncertain" if uncertain else "ben", why)] += 1
    for k, v in sorted(stats.items(), key=str):
        print(k, v)


if __name__ == "__main__":
    main()
