"""Step 4: verification tools an analyst (or LLM) can call to check an alert.

Every tool sees only data from BEFORE the alert's chunk ends (no peeking ahead),
and returns plain text meant to be pasted into a verification prompt.

  baseline(alert)    how common each flagged message type is on previous days
  ip_history(alert)  everything the flagged IPs did in the last 30 minutes
  audit_exec(alert)  commands executed on the server around the alert (audit log)
  suricata(alert)    network IDS alerts around the alert
  alert_history(alert)  how often this Suricata alarm normally fires, overall and
                        from this source IP (alert cases only)

An `alert` is a dict with: host, start, end (ISO strings), lines (flagged log text,
each prefixed with "(source) ").
"""
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import extract_windows as ew

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
AUDIT_DIR = os.path.join(BASE, "tools_data", "audit_exec")
LOCAL_IPS = {"127.0.0.1", "::1"}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAX_OUT = 4000  # characters of tool output passed to the LLM


def _cap(text):
    return text if len(text) <= MAX_OUT else text[:MAX_OUT] + "\n... (truncated)"


@lru_cache(maxsize=4)
def host_logs(host):
    """All log lines of a host as (ts, source, text), sorted by time."""
    rows = []
    for src, rel in ew.sources(host).items():
        for _, ts, text, _, _ in ew.load(host, rel):
            if ts:
                rows.append((ts, src, text))
    rows.sort(key=lambda r: r[0])
    return rows


def template_any(src, text):
    if src == "apache_access":
        m = re.search(r'"(\w+) ([^ ?"]*)', text)
        return f"{m.group(1)} {m.group(2)}" if m else text[:80]
    return ew.template(src, text)


def _split(line):
    """'(syslog) Mar  4 ...' -> ('syslog', 'Mar  4 ...')"""
    m = re.match(r"\((\w+)\) (.*)", line)
    return (m.group(1), m.group(2)) if m else ("syslog", line)


# ---------------------------------------------------------------- baseline
def baseline(alert, max_types=8):
    end = datetime.fromisoformat(alert["end"])
    today = end.date()
    types = []
    for line in alert["lines"]:
        key = template_any(*_split(line))
        if key not in types:
            types.append(key)
    types = types[:max_types]

    per_day = defaultdict(Counter)
    last_hour = Counter()
    for ts, src, text in host_logs(alert["host"]):
        if ts > end:
            break
        key = template_any(src, text)
        if key not in types:
            continue
        if ts.date() < today:
            per_day[key][ts.date()] += 1
        elif ts >= end - timedelta(hours=1):
            last_hour[key] += 1

    days = sorted({ts.date() for ts, _, _ in host_logs(alert["host"]) if ts.date() < today})
    out = [f"Message-type frequency on this server. Previous days ({len(days)}): "
           f"{days[0] if days else '-'} to {days[-1] if days else '-'}."]
    for key in types:
        counts = [per_day[key][d] for d in days]
        avg = sum(counts) / len(days) if days else 0
        seen = sum(c > 0 for c in counts)
        out.append(f"- \"{key[:110]}\": avg {avg:.1f}/day on previous days "
                   f"(seen on {seen}/{len(days)} days); {last_hour[key]} in the last hour")
    return _cap("\n".join(out))


# -------------------------------------------------------------- ip_history
def ip_history(alert, minutes=30, max_ips=3, samples=8):
    end = datetime.fromisoformat(alert["end"])
    since = end - timedelta(minutes=minutes)
    ips = []
    for line in alert["lines"]:
        for ip in IP_RE.findall(line):
            if ip not in LOCAL_IPS and ip not in ips:
                ips.append(ip)
    if not ips:
        return "No external IP addresses appear in the flagged lines."

    out = []
    for ip in ips[:max_ips]:
        recent, earlier_days = [], Counter()
        for ts, src, text in host_logs(alert["host"]):
            if ts > end:
                break
            if ip not in text:
                continue
            if ts >= since:
                recent.append((ts, src, text))
            elif ts.date() < end.date():
                earlier_days[ts.date()] += 1
        by_src = Counter(s for _, s, _ in recent)
        paths = Counter(m.group(1) for _, s, t in recent if s == "apache_access"
                        for m in [re.search(r'"\w+ ([^ ?"]*)', t)] if m)
        agents = Counter(t.rsplit('"', 2)[-2][:60] for _, s, t in recent
                         if s == "apache_access" and t.count('"') >= 6)
        failed = sum("FAILED LOGIN" in t or "authentication failure" in t for _, _, t in recent)
        ok = sum("Login success" in t for _, _, t in recent)
        out.append(f"IP {ip}: {len(recent)} log lines in the last {minutes} min "
                   f"({dict(by_src)}); failed logins {failed}, successful logins {ok}; "
                   f"seen on {len(earlier_days)} previous days ({sum(earlier_days.values())} lines).")
        if paths:
            out.append("  top URLs: " + ", ".join(f"{p} x{n}" for p, n in paths.most_common(6)))
        if agents:
            out.append("  user agents: " + "; ".join(f"{a} x{n}" for a, n in agents.most_common(3)))
        pick = recent[:samples // 2] + recent[-(samples // 2):] if len(recent) > samples else recent
        for ts, src, text in pick:
            out.append(f"  [{ts.time()}] ({src}) {text[:180]}")
    return _cap("\n".join(out))


# -------------------------------------------------------------- audit_exec
AUDIT_TS = re.compile(r"msg=audit\((\d+)\.\d+:(\d+)\)")


@lru_cache(maxsize=4)
def audit_records(host):
    """(ts, uid, command line) for every execve on the host."""
    path = os.path.join(AUDIT_DIR, f"{host}.log")
    if not os.path.exists(path):
        return None
    syscalls, execs = {}, {}
    with open(path, errors="replace") as f:
        for line in f:
            m = AUDIT_TS.search(line)
            if not m:
                continue
            ts = datetime.fromtimestamp(int(m.group(1)), timezone.utc).replace(tzinfo=None)
            if line.startswith("type=SYSCALL"):
                uid = re.search(r" uid=(\d+)", line)
                syscalls[m.group(2)] = (ts, uid.group(1) if uid else "?")
            elif line.startswith("type=EXECVE"):
                execs[m.group(2)] = (ts, _execve_cmd(line))
    rows = [(ts, syscalls.get(i, (ts, "?"))[1], cmd) for i, (ts, cmd) in execs.items()]
    rows.sort()
    return rows


def _execve_cmd(line):
    args = []
    for _, quoted, hexed in re.findall(r' a(\d+)=(?:"([^"]*)"|([0-9A-F]+))', line):
        if quoted or not hexed:
            args.append(quoted)
        else:
            try:
                args.append(bytes.fromhex(hexed).decode(errors="replace"))
            except ValueError:
                args.append(hexed)
    return " ".join(args)[:200]


USERS = {"0": "root", "33": "www-data (web server)"}


def audit_exec(alert, before_minutes=10, max_cmds=25):
    rows = audit_records(alert["host"])
    if rows is None:
        return "Audit log not available for this host."
    start = datetime.fromisoformat(alert["start"]) - timedelta(minutes=before_minutes)
    end = datetime.fromisoformat(alert["end"])
    recent = [(ts, uid, cmd) for ts, uid, cmd in rows if start <= ts <= end]
    if not recent:
        return f"No commands were executed on the server between {start.time()} and {end.time()}."
    counts = Counter((uid, cmd) for _, uid, cmd in recent)
    by_web = sum(n for (uid, _), n in counts.items() if uid == "33")
    out = [f"{len(recent)} commands executed between {start.time()} and {end.time()} "
           f"({by_web} by the web server user www-data). Distinct commands:"]
    for (uid, cmd), n in counts.most_common(max_cmds):
        out.append(f"- [{USERS.get(uid, 'uid ' + uid)}] x{n}: {cmd}")
    return _cap("\n".join(out))


# ---------------------------------------------------------------- suricata
@lru_cache(maxsize=4)
def suricata_alerts(host):
    return [(ts, text) for _, ts, text, _, _ in ew.load(host, "suricata/fast.log") if ts]


def suricata(alert, before_minutes=5):
    start = datetime.fromisoformat(alert["start"]) - timedelta(minutes=before_minutes)
    end = datetime.fromisoformat(alert["end"])
    hits = [t for ts, t in suricata_alerts(alert["host"]) if start <= ts <= end]
    if not hits:
        return f"Suricata raised no network alerts between {start.time()} and {end.time()}."
    sig = Counter(re.search(r"\] (.*?) \[\*\*\]", t).group(1) if "[**]" in t else t[:80] for t in hits)
    flows = Counter(re.search(r"\} (\S+):\d+ -> (\S+):(\d+)", t).groups() if "->" in t else ("?",) for t in hits)
    out = [f"Suricata raised {len(hits)} network alerts between {start.time()} and {end.time()}:"]
    out += [f"- x{n}: {s}" for s, n in sig.most_common(8)]
    out.append("Top flows (src -> dst:port): " + ", ".join(
        f"{f[0]} -> {f[1]}:{f[2]} x{n}" if len(f) == 3 else f"{f} x{n}" for f, n in flows.most_common(4)))
    return _cap("\n".join(out))


# ----------------------------------------------------------- alert_history
SIG_RE = re.compile(r"\[\*\*\] \[[\d:]+\] (.*?) \[\*\*\].*\{\w+\} ([\d.]+):\d+ ->")


def alert_history(alert, recent_hours=1):
    """For a Suricata alert case: is this alarm, from this IP, normal here?"""
    sig, ip = alert.get("signature"), alert.get("src_ip")
    if not sig:
        return "Not applicable: this tool needs a Suricata alert."
    start = datetime.fromisoformat(alert["start"])
    end = datetime.fromisoformat(alert["end"])
    per_day, per_day_ip, recent_ip, recent_all = Counter(), Counter(), 0, 0
    days = set()
    for ts, text in suricata_alerts(alert["host"]):
        if ts >= start:
            break
        m = SIG_RE.search(text)
        if not m:
            continue
        if ts.date() < start.date():
            days.add(ts.date())
        if m.group(1) != sig:
            continue
        if ts.date() < start.date():
            per_day[ts.date()] += 1
            if m.group(2) == ip:
                per_day_ip[ts.date()] += 1
        elif ts >= start - timedelta(hours=recent_hours):
            recent_all += 1
            recent_ip += m.group(2) == ip
    days = sorted(days)
    n = len(days) or 1
    case_minutes = max((end - start).total_seconds() / 60, 1)
    return "\n".join([
        f"Alarm \"{sig}\" on this server, before this case:",
        f"- all sources: avg {sum(per_day.values()) / n:.1f} per day on {len(days)} previous days "
        f"(seen on {len(per_day)}/{len(days)} days); {recent_all} in the hour before this case",
        f"- from {ip}: avg {sum(per_day_ip.values()) / n:.1f} per day (seen on {len(per_day_ip)}/{len(days)} days); "
        f"{recent_ip} in the hour before this case",
        f"- this case: {alert.get('n_alarms', '?')} alarms in {case_minutes:.0f} minute(s)",
    ])


# ---------------------------------------------------------------- overview
UA_RE = re.compile(r'"([^"]*)"$')


def top_external_ips(alert, server, n=3):
    """Busiest remote IPs in the alert window (web requests + Suricata alarms)."""
    start, end = datetime.fromisoformat(alert["start"]), datetime.fromisoformat(alert["end"])
    c = Counter()
    for ts, src, text in host_logs(alert["host"]):
        if ts > end:
            break
        if ts >= start and src == "apache_access":
            ip = text.split(" ", 1)[0]
            if ip not in LOCAL_IPS and ip != server:
                c[ip] += 1
    for ts, text in suricata_alerts(alert["host"]):
        if start <= ts <= end:
            for ip in IP_RE.findall(text):
                if ip not in LOCAL_IPS and ip != server:
                    c[ip] += 1
    return [ip for ip, _ in c.most_common(n)]


def overview(alert):
    """Summary of everything in the alert window, like the overview query of
    Eilertsen et al.: volumes, Suricata alarms, busiest clients, failed logins."""
    start, end = datetime.fromisoformat(alert["start"]), datetime.fromisoformat(alert["end"])
    per_src, ips, statuses, agents = Counter(), Counter(), Counter(), Counter()
    failed = ok = 0
    for ts, src, text in host_logs(alert["host"]):
        if ts > end:
            break
        if ts < start:
            continue
        per_src[src] += 1
        if src == "apache_access":
            ips[text.split(" ", 1)[0]] += 1
            m = re.search(r'" (\d{3}) ', text)
            if m:
                statuses[m.group(1)[0] + "xx"] += 1
            ua = UA_RE.search(text)
            if ua:
                agents[ua.group(1)[:50]] += 1
        failed += "FAILED LOGIN" in text or "authentication failure" in text
        ok += "Login success" in text
    sur = [t for ts, t in suricata_alerts(alert["host"]) if start <= ts <= end]
    sig = Counter(m.group(1) for t in sur for m in [SIG_RE.search(t)] if m)
    out = [f"Overview of host activity from {start} to {end}:",
           f"- log lines per source: {dict(per_src)}",
           f"- web requests by client IP (top 5): " + ", ".join(f"{ip} x{n}" for ip, n in ips.most_common(5)),
           f"- HTTP status classes: {dict(statuses)}",
           f"- top user agents: " + "; ".join(f"{a} x{n}" for a, n in agents.most_common(4)),
           f"- failed logins: {failed}, successful web logins: {ok}",
           f"- Suricata alarms: {len(sur)}" + ("" if not sur else "; top signatures: " +
                                              "; ".join(f"{s} x{n}" for s, n in sig.most_common(5)))]
    return _cap("\n".join(out))


TOOLS = {"baseline": baseline, "ip_history": ip_history,
         "audit_exec": audit_exec, "suricata": suricata, "alert_history": alert_history,
         "overview": overview}
