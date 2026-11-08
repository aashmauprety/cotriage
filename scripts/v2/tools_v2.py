"""Evidence tools for Setting C (AIT-LDS v2). Every tool reads only data up to the end of the case.

  alert_history  how often this alert fires on this host per day, overall and from this source
  siem_context   other alerts on the same host or from the same source in the 30 minutes before
  ip_activity    what the remote address did in the last 30 minutes (web requests, logins,
                 DNS queries, VPN session) and its activity on previous days
  host_activity  account activity on the alerted host in the last 30 minutes (sshd, su, sudo,
                 audit login/session records), compared with previous days
"""
import bisect
import os
import pickle
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
WINDOW = 1800
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IDX = {}


def index(scen):
    if scen not in _IDX:
        with open(os.path.join(BASE, "AIT-LDS-v2", scen, "index.pkl"), "rb") as f:
            idx = pickle.load(f)
        idx["_t"] = {k: [r[0] for r in v] for k, v in idx.items() if isinstance(v, list)}
        idx["_day0"] = min(r[0] for r in idx["alerts"])
        _IDX[scen] = idx
    return _IDX[scen]


def window(idx, kind, t0, t1):
    ts = idx["_t"][kind]
    return idx[kind][bisect.bisect_left(ts, t0):bisect.bisect_right(ts, t1)]


def norm_host(idx, h):
    h = idx["agent_host"].get(h, h) or "?"
    return h.replace("-", "_")


def fmt(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%m-%d %H:%M:%S")


def prev_days(idx, t):
    """Number of whole days of data before the day of t."""
    day = lambda x: int(x // 86400)
    return max(day(t) - day(idx["_day0"]), 0)


def remote_ips(case, idx=None):
    """The remote party: whichever of source and destination is not the alerted host itself
    (e.g. for "SMTP invalid reply" the mail server is the source and the scanner the destination).
    For DNS alarms it is the source, the host that sends the queries."""
    own = {case["host"]}
    if idx is not None:
        own |= {ip for ip, h in idx["agent_host"].items() if h == case["host"] or ip == case["host"]}
    ends = [x for x in (case.get("src"), case.get("dst")) if x]
    ips = [x for x in ends if x not in own] + [x for x in ends if x in own]
    if "DNS" in case["desc"] and case.get("src"):
        ips = [case["src"]] + ips  # a DNS alarm is about the host that sends the queries, not the DNS server
    for e in case.get("examples", []):
        ips += IP_RE.findall(e)
    out = []
    for ip in ips:
        if ip and ip not in out and not ip.startswith(("127.", "0.")):
            out.append(ip)
    return out[:2]


def alert_history(case):
    idx = index(case["scenario"])
    host, end = norm_host(idx, case["host"]), case["end"]
    days = prev_days(idx, end)
    today0 = end - (end % 86400)
    same = [a for a in window(idx, "alerts", idx["_day0"], end) if a[4] == case["desc"] and norm_host(idx, a[1]) == host]
    before = [a for a in same if a[0] < today0]
    today = [a for a in same if a[0] >= today0]
    src = case.get("src")
    lines = [f"Alert '{case['desc']}' on host {host}:",
             f"  previous {days} day(s): {len(before)} alerts, {len(before) / max(days, 1):.1f} per day"
             f" from {len({a[5] for a in before if a[5]})} distinct sources",
             f"  today until the end of this case: {len(today)} alerts"]
    if src:
        sb = [a for a in before if a[5] == src]
        lines.append(f"  from source {src}: {len(sb)} alerts on previous days ({len(sb) / max(days, 1):.1f} per day), "
                     f"{sum(1 for a in today if a[5] == src)} today")
    if days == 0:
        lines.append("  no earlier days of data are available")
    elif not before:
        lines.append("  this alert has never fired on this host before today")
    return "\n".join(lines)


def siem_context(case):
    idx = index(case["scenario"])
    host, t0, t1 = norm_host(idx, case["host"]), case["start"] - WINDOW, case["end"]
    src = case.get("src")
    other = [a for a in window(idx, "alerts", t0, t1) if a[4] != case["desc"]
             and (norm_host(idx, a[1]) == host or (src and src in (a[5], a[6])))]
    if not other:
        return f"No other alerts on host {host}" + (f" or involving {src}" if src else "") + " in the 30 minutes before and during this case."
    c = Counter((a[4], norm_host(idx, a[1])) for a in other)
    lines = [f"Other alerts on host {host}" + (f" or involving {src}" if src else "") +
             f" from {fmt(t0)} to {fmt(t1)}: {len(other)} alerts, {len(c)} distinct (alert, host) pairs"]
    for (d, h), n in c.most_common(8):
        lines.append(f"  {n:5d} x {d[:80]} (host {h})")
    if src:
        lines.append(f"  source {src} triggered alerts on {len({norm_host(idx, a[1]) for a in other if src in (a[5], a[6])})} host(s)")
    return "\n".join(lines)


def ip_activity(case):
    idx = index(case["scenario"])
    ips = remote_ips(case, idx)
    if not ips:
        return "The alert names no remote address."
    if case.get("src") or case.get("dst"):
        ips = ips[:1]  # the remote party only
    t1 = case["end"]
    t0 = t1 - WINDOW
    days = prev_days(idx, t1)
    today0 = t1 - (t1 % 86400)
    out = []
    for ip in ips:
        http = [r for r in window(idx, "http", t0, t1) if r[2] == ip]
        lines = [f"Activity of {ip} from {fmt(t0)} to {fmt(t1)}:"]
        if http:
            st = Counter(r[5] // 100 * 100 for r in http)
            ua = Counter(r[6] for r in http)
            paths = Counter(r[4].split("?")[0] for r in http)
            lines.append(f"  web requests: {len(http)} on hosts {', '.join(sorted({r[1] for r in http}))}; status "
                         + ", ".join(f"{k}xx: {v}" for k, v in sorted(st.items())).replace("00xx", "xx"))
            lines.append("  user agents: " + "; ".join(f"{u[:60]} ({n})" for u, n in ua.most_common(3)))
            lines.append(f"  distinct paths: {len(paths)}; most requested: " + ", ".join(f"{p[:50]} ({n})" for p, n in paths.most_common(4)))
            q = [r for r in http if "?" in r[4]]
            if q:
                lines.append("  latest requests with parameters: " + " | ".join(f"{r[3]} {r[4][:70]}" for r in q[-3:]))
        else:
            lines.append("  web requests: none")
        mail = [r for r in window(idx, "mail", t0, t1) if r[4] == ip]
        if mail:
            ok = sum(r[5] for r in mail)
            lines.append(f"  mail/webmail logins: {ok} successful, {len(mail) - ok} failed, users: "
                         + ", ".join(f"{u} ({n})" for u, n in Counter(r[3] for r in mail).most_common(4)))
        auth = [r for r in window(idx, "auth", t0, t1) if ip in r[3]]
        if auth:
            lines.append(f"  ssh/auth events: {len(auth)}; e.g. " + " | ".join(f"{r[1]}: {r[3][:90]}" for r in auth[-3:]))
        dns = [r for r in window(idx, "dns", t0, t1) if r[2] == ip]
        if dns:
            b = Counter(r[3] for r in dns)
            lines.append(f"  DNS queries: {len(dns)} to {len(b)} domains, mean name length {sum(r[4] for r in dns) / len(dns):.0f}; top: "
                         + ", ".join(f"{d} ({n}, mean name length {sum(r[4] for r in dns if r[3] == d) / n:.0f})"
                                     for d, n in b.most_common(3)))
        vpn = [r for r in window(idx, "vpn", t1 - 86400, t1) if r[4] == ip or r[3] == ip]
        if vpn:
            r = vpn[-1]
            lines.append(f"  VPN: {r[4]} assigned to user {r[2]} connecting from {r[3]} at {fmt(r[0])}")
        hist_http = sum(1 for r in window(idx, "http", idx["_day0"], today0) if r[2] == ip)
        hist_dns = sum(1 for r in window(idx, "dns", idx["_day0"], today0) if r[2] == ip)
        lines.append(f"  previous {days} day(s): {hist_http / max(days, 1):.0f} web requests and {hist_dns / max(days, 1):.0f} DNS queries per day")
        out.append("\n".join(lines))
    return "\n".join(out)


def host_activity(case):
    idx = index(case["scenario"])
    host, t1 = norm_host(idx, case["host"]), case["end"]
    t0 = t1 - WINDOW
    days = prev_days(idx, t1)
    today0 = t1 - (t1 % 86400)
    auth = [r for r in window(idx, "auth", t0, t1) if r[1] == host]
    audit = [r for r in window(idx, "audit", t0, t1) if r[1] == host]
    lines = [f"Account activity on host {host} from {fmt(t0)} to {fmt(t1)}:"]
    if auth:
        c = Counter((r[2], re.sub(r"\d+", "#", r[3])[:110]) for r in auth)
        lines.append(f"  auth.log: {len(auth)} events")
        for (prog, msg), n in c.most_common(6):
            lines.append(f"    {n:3d} x {prog}: {msg}")
    else:
        lines.append("  auth.log: no events")
    if audit:
        c = Counter((r[2], r[3], r[4], r[6]) for r in audit)
        lines.append(f"  audit: {len(audit)} login/session records; " + "; ".join(
            f"{typ} acct={acct} exe={exe} {res} ({n})" for (typ, acct, exe, res), n in c.most_common(5)))
    prev_auth = [r for r in window(idx, "auth", idx["_day0"], today0) if r[1] == host]
    prev_audit = [r for r in window(idx, "audit", idx["_day0"], today0) if r[1] == host]
    seen_pairs = {(r[2], r[3].split(" ")[0]) for r in prev_auth}
    new = sorted({f"{r[2]}: {r[3][:80]}" for r in auth if (r[2], r[3].split(" ")[0]) not in seen_pairs})
    known_accts = {(r[3], r[4]) for r in prev_audit}
    new_acct = sorted({f"{r[3]} via {r[4]}" for r in audit if (r[3], r[4]) not in known_accts})
    lines.append(f"  previous {days} day(s): {len(prev_auth) / max(days, 1):.0f} auth.log events and "
                 f"{len(prev_audit) / max(days, 1):.0f} audit records per day")
    if new:
        lines.append("  event types never seen on this host before today: " + " | ".join(new[:4]))
    if new_acct:
        lines.append("  accounts/programs never seen in audit before today: " + ", ".join(new_acct[:5]))
    return "\n".join(lines)


TOOLS = {"alert_history": alert_history, "siem_context": siem_context,
         "ip_activity": ip_activity, "host_activity": host_activity}
