"""Parse the server-side logs of one AIT-LDS v2 scenario into a compact, time-sorted index for the tools.

Only logs a SOC would have are read: Apache/Horde access logs, auth.log, mail/Horde logins,
dnsmasq queries, OpenVPN sessions, audit login/session records, and the alert stream itself.
The attacker's and the simulated users' own logs (attacker_*/, *_employee_*/, ext_user_*/) and
the label files are never read.

Usage: python3 -I scripts/v2/index_v2.py <scenario> [...]  ->  AIT-LDS-v2/<scenario>/index.pkl
"""
import glob
import gzip
import json
import os
import pickle
import re
import sys
from datetime import datetime, timezone

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
SKIP_HOSTS = re.compile(r"^(attacker|internal_employee|remote_employee|ext_user)")
YEAR = 2022

HTTP_RE = re.compile(r'^(?:\S+:\d+ )?(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
SYSLOG_RE = re.compile(r"^(\w{3} +\d+ \d\d:\d\d:\d\d) (\S+) ([\w\-./]+)(?:\[\d+\])?: (.*)$")
DNS_RE = re.compile(r"query\[(\w+)\] (\S+) from (\S+)")
VPN_IP_RE = re.compile(r"^(\S+ \S+) (\S+)/(\S+):\d+ MULTI: primary virtual IP for \S+: (\S+)")
AUDIT_RE = re.compile(r"type=(USER_\w+|LOGIN|CRED_\w+) msg=audit\((\d+\.\d+):\d+\).*?acct=\"?([^\" ]*)\"?.*?exe=\"([^\"]*)\".*?addr=(\S+).*?res=(\w+)")
DOVECOT_RE = re.compile(r"imap-login: (Login|Disconnected \(auth failed[^)]*\)|Aborted login[^:]*): user=<([^>]*)>.*?rip=([\d.]+)")
HORDE_RE = re.compile(r"\[horde\] (Login success|FAILED LOGIN|User \S+ logged out)\D*?(?:for )?(\S+)? .*?\(([\d.]+)\)")


def syslog_ts(s):
    return datetime.strptime(f"{YEAR} {s}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


def files(root, pattern):
    for host_dir in sorted(glob.glob(os.path.join(root, "gather", "*"))):
        host = os.path.basename(host_dir)
        if SKIP_HOSTS.match(host):
            continue
        for p in sorted(glob.glob(os.path.join(host_dir, "logs", pattern), recursive=True)):
            yield host, p


def lines(path):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", errors="replace") as f:
        for l in f:
            yield l.rstrip("\n")


def build(scen):
    root = os.path.join(BASE, "AIT-LDS-v2", scen)
    idx = {"http": [], "auth": [], "mail": [], "dns": [], "vpn": [], "audit": []}
    for host, p in files(root, "**/*access*.log*"):
        for l in lines(p):
            m = HTTP_RE.match(l)
            if not m or m.group(1) in ("::1", "127.0.0.1"):
                continue
            t = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").timestamp()
            idx["http"].append((t, host, m.group(1), m.group(3), m.group(4)[:120], int(m.group(5)), m.group(6)[:90]))
    for host, p in files(root, "auth.log*"):
        for l in lines(p):
            m = SYSLOG_RE.match(l)
            if not m or m.group(3) in ("CRON", "systemd-logind", "systemd") or "pam_unix(cron" in l:
                continue
            idx["auth"].append((syslog_ts(m.group(1)), host, m.group(3), m.group(4)[:200]))
    for host, p in list(files(root, "mail.log*")) + list(files(root, "user.log*")):
        for l in lines(p):
            m = SYSLOG_RE.match(l)
            if not m:
                continue
            d = DOVECOT_RE.search(m.group(4))
            if d:
                idx["mail"].append((syslog_ts(m.group(1)), host, "imap", d.group(2), d.group(3), d.group(1).startswith("Login")))
                continue
            h = HORDE_RE.search(m.group(4))
            if h and not h.group(1).startswith("User"):
                idx["mail"].append((syslog_ts(m.group(1)), host, "webmail", h.group(2) or "?", h.group(3), h.group(1) == "Login success"))
    for host, p in files(root, "dnsmasq.log*"):
        for l in lines(p):
            d = DNS_RE.search(l)  # dnsmasq lines have no host name: "Jan 21 00:00:09 dnsmasq[3468]: query[A] ..."
            if d:
                name = d.group(2)
                base = ".".join(name.split(".")[-2:])
                idx["dns"].append((syslog_ts(l[:15]), host, d.group(3), base, len(name), d.group(1)))
    for host, p in files(root, "openvpn.log*"):
        for l in lines(p):
            m = VPN_IP_RE.match(l)
            if m:
                t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                idx["vpn"].append((t, host, m.group(2), m.group(3), m.group(4)))
    for host, p in files(root, "audit/audit.log*"):
        for l in lines(p):
            m = AUDIT_RE.search(l)
            if m:
                idx["audit"].append((float(m.group(2)), host, m.group(1), m.group(3), os.path.basename(m.group(4)), m.group(5), m.group(6)))
    # alert stream without labels: what the SIEM shows
    alerts, seen = [], set()
    for l in open(os.path.join(BASE, "alerts_v2", f"{scen}.jsonl")):
        a = json.loads(l)
        if a["location"] and a["location"].endswith("fast.log"):
            continue  # duplicate of the eve.json alarm
        key = (a["rule"], a["full_log"], int(a["t"]))
        if a["full_log"] and key in seen:
            continue
        seen.add(key)
        alerts.append((a["t"], a["host"] or a["agent_ip"], a["rule"], a["level"], a["desc"], a["src"], a["dst"]))
    idx["alerts"] = alerts
    # agent address -> host name, from alerts that carry both
    amap = {}
    for l in open(os.path.join(BASE, "alerts_v2", f"{scen}.jsonl")):
        a = json.loads(l)
        if a["host"] and a["agent_ip"]:
            amap.setdefault(a["agent_ip"], a["host"])
    idx["agent_host"] = amap
    for k in idx:
        if isinstance(idx[k], list):
            idx[k].sort(key=lambda x: x[0])
    with open(os.path.join(root, "index.pkl"), "wb") as f:
        pickle.dump(idx, f)
    print(scen, {k: len(v) for k, v in idx.items()})


if __name__ == "__main__":
    for s in sys.argv[1:]:
        build(s)
