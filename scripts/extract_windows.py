"""Step 1: extract 12 labeled log windows from AIT-LDS v1.1.

Per host (4 mail servers) we cut 3 windows:
  recon     - nmap -> nikto -> smtp VRFY enumeration
  intrusion - hydra brute force -> webshell upload -> mail-curl -> webshell commands / exim exploit
  benign    - same clock time as the intrusion window, one day earlier (Mar 3), no attack activity

Ground truth comes from the AIT-LDS label files, which are line-aligned with the
data files and hold "time_label,line_label" (CRLF line endings):
  line_label != "0"  -> the line was produced by the attack (positive)
  time_label != "0"  -> an attack phase was running at that time (context only;
                        many such lines are benign user traffic)
Suricata alerts are attached as an IDS baseline, NOT as ground truth.

Usage: python3 scripts/extract_windows.py [--out windows]
"""
import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "AIT-LDS-v1.1")
HOSTS = ["mail.cup.com", "mail.insect.com", "mail.onion.com", "mail.spiral.com"]

# Non-overlapping sources. messages/user.log/mail.log/mail.info/daemon.log are
# rsyslog subsets of syslog; audit (1 GB zipped per host) and eve.json are left
# for the verification-tool stage.
def sources(host):
    return {
        "syslog": "syslog",
        "auth": "auth.log",
        "apache_access": f"apache2/{host}-access.log",
        "apache_error": f"apache2/{host}-error.log",
        "exim": "exim4/mainlog",
    }

RECON = {"nmap", "nikto", "vrfy"}
# A message template counts as an attack side effect when, during attack phases, it
# occurs at >= BURST_RATIO x its hourly rate on the other days, at least BURST_MIN times.
BURST_RATIO = 20
BURST_MIN = 3
INTRUSION = {"hydra", "upload", "mail-curl", "webshell"}
PAD = timedelta(minutes=1)


# insect has an "okay-upload-webshell" time label at 12:37, ~75 min before the
# attack starts, covering only benign IMAP logins (apparently a pre-test run).
IGNORED_TAGS = {"okay-upload-webshell"}


def phase_of(tag):
    return "webshell" if tag.startswith("webshell") else tag


def parse_ts(line):
    m = re.search(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})", line)  # apache access
    if m:
        return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S")
    m = re.match(r"\[\w{3} (\w{3} \d{2} \d{2}:\d{2}:\d{2})\.\d+ (\d{4})\]", line)  # apache error
    if m:
        return datetime.strptime(f"{m.group(2)} {m.group(1)}", "%Y %b %d %H:%M:%S")
    m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)  # exim
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    m = re.match(r"(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2})", line)  # suricata fast.log
    if m:
        return datetime.strptime(m.group(1), "%m/%d/%Y-%H:%M:%S")
    m = re.match(r"(\w{3}\s+\d+ \d{2}:\d{2}:\d{2})", line)  # syslog (no year)
    if m:
        return datetime.strptime("2020 " + m.group(1), "%Y %b %d %H:%M:%S")
    return None


def load(host, rel):
    """Yield (line_no, ts, text, time_label, line_label); lines without a parseable
    timestamp (continuations) inherit the previous timestamp."""
    with open(os.path.join(ROOT, "data", host, rel), errors="replace") as fd, \
         open(os.path.join(ROOT, "labels", host, rel)) as fl:
        last = None
        for i, (line, lab) in enumerate(zip(fd, fl), 1):
            t_lab, l_lab = lab.strip().split(",")
            ts = parse_ts(line) or last
            last = ts
            yield i, ts, line.rstrip("\n"), t_lab, l_lab


def template(src, text):
    """Reduce a log line to its message type: drop the timestamp/host prefix and
    mask the variable parts (numbers, IPs, user names, ids)."""
    if src in ("syslog", "auth"):
        parts = text.split(None, 4)
        text = parts[4] if len(parts) > 4 else text
    elif src == "exim":
        text = text.split(None, 2)[-1]
    elif src == "apache_error":
        text = re.sub(r"^(\[[^\]]*\]\s*)+", "", text)
    text = re.sub(r"<[^>]*>", "<*>", text)
    text = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "IP", text)
    text = re.sub(r"\b(for|user|ruser|imap|pop3)([ =(])\w+", r"\1\2*", text)
    text = re.sub(r"/var/mail/\w+", "/var/mail/*", text)
    text = re.sub(r"\b[\w-]{16,}\b", "ID", text)
    text = re.sub(r"\d+", "0", text)
    return text[:160]


def burst_templates(recs_by_src, attack_day, phase_hours):
    """Message templates whose rate during attack phases far exceeds their normal
    rate on the other days: lines the attack produced as side effects."""
    in_phase, other = Counter(), Counter()
    first = min(r[1] for rs in recs_by_src.values() for r in rs if r[1])
    last = max(r[1] for rs in recs_by_src.values() for r in rs if r[1])
    other_hours = (last - first).total_seconds() / 3600 - 24
    for src, recs in recs_by_src.items():
        if src == "apache_access":  # request lines vary per URL; direct attack lines are labeled
            continue
        for _, ts, text, t_lab, _ in recs:
            if not ts:
                continue
            key = (src, template(src, text))
            if ts.date() == attack_day:
                if t_lab != "0" and t_lab not in IGNORED_TAGS:
                    in_phase[key] += 1
            else:
                other[key] += 1
    burst = set()
    for key, n in in_phase.items():
        base_rate = max(other[key], 1) / other_hours  # floor: once in the other days
        if n >= BURST_MIN and n / phase_hours >= BURST_RATIO * base_rate:
            burst.add(key)
    return burst


def phase_ranges(records):
    """Attack phase -> [first, last] timestamp, using the time-label column."""
    rng = {}
    for _, ts, _, t_lab, l_lab in records:
        for tag in {t_lab, l_lab} - {"0"} - IGNORED_TAGS:
            p = phase_of(tag)
            a, b = rng.get(p, (ts, ts))
            rng[p] = (min(a, ts), max(b, ts))
    return rng


def build_window(host, wid, kind, start, end, recs_by_src, suricata, burst):
    lines = []
    for src, recs in recs_by_src.items():
        for n, ts, text, t_lab, l_lab in recs:
            if ts and start <= ts <= end:
                active = t_lab != "0" and t_lab not in IGNORED_TAGS
                lines.append({
                    "ts": ts.isoformat(), "source": src, "line_no": n, "text": text,
                    "malicious": l_lab != "0",
                    "attack_label": None if l_lab == "0" else l_lab,
                    "active_phase": None if t_lab == "0" else t_lab,
                    # unlabeled line of a message type that bursts only during the attack
                    "side_effect": (l_lab == "0" and active
                                    and (src, template(src, text)) in burst),
                })
    lines.sort(key=lambda r: (r["ts"], r["source"], r["line_no"]))
    for i, r in enumerate(lines):
        r["id"] = i

    mal = [r for r in lines if r["malicious"]]
    per_phase = defaultdict(lambda: {"first": None, "last": None, "malicious_lines": 0})
    for r in mal:
        p = per_phase[phase_of(r["attack_label"])]
        p["first"] = p["first"] or r["ts"]
        p["last"] = r["ts"]
        p["malicious_lines"] += 1
    # Phases with only time labels (e.g. webshell commands mostly leave no
    # directly-labeled lines outside the audit log) still count as present.
    present = sorted({phase_of(r["active_phase"]) for r in lines
                      if r["active_phase"] and r["active_phase"] not in IGNORED_TAGS} | set(per_phase))
    attacker_ips = Counter(
        r["text"].split()[0] for r in mal if r["source"] == "apache_access")

    sur = [{"ts": ts.isoformat(), "text": text,
            "malicious": l_lab != "0", "attack_label": None if l_lab == "0" else l_lab}
           for _, ts, text, _, l_lab in suricata if ts and start <= ts <= end]

    return {
        "window_id": wid,
        "host": host,
        "kind": kind,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "sources": list(recs_by_src),
        "ground_truth": {
            "is_attack": bool(mal),
            "phases_present": present,
            "phase_detail": dict(per_phase),
            "attacker_ips": [ip for ip, _ in attacker_ips.most_common()],
            "n_lines": len(lines),
            "n_malicious": len(mal),
            "malicious_by_source": dict(Counter(r["source"] for r in mal)),
            "n_side_effect": sum(r["side_effect"] for r in lines),
        },
        "suricata_baseline": {
            "note": "IDS output for comparison only; not ground truth",
            "n_alerts": len(sur),
            "n_alerts_on_attack_traffic": sum(a["malicious"] for a in sur),
            "alerts": sur,
        },
        "lines": lines,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(ROOT), "windows"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    index = []
    for host in HOSTS:
        recs = {s: list(load(host, rel)) for s, rel in sources(host).items()}
        suricata = list(load(host, "suricata/fast.log"))
        rng = phase_ranges([r for rs in recs.values() for r in rs])

        def span(phases):
            ps = [rng[p] for p in phases if p in rng]
            return min(a for a, _ in ps), max(b for _, b in ps)

        r0, r1 = span(RECON)
        i0, i1 = span(INTRUSION)
        # recon and intrusion are separated by ~3 min; split the gap so they never overlap
        cut = min(r1 + PAD, r1 + (i0 - r1) / 2)
        attack_spans = [(r0 - PAD, cut), (max(i0 - PAD, cut + timedelta(seconds=1)), i1 + PAD)]
        phase_hours = sum((b - a).total_seconds() for a, b in attack_spans) / 3600
        burst = burst_templates(recs, r0.date(), phase_hours)
        windows = [
            ("recon", r0 - PAD, cut),
            ("intrusion", max(i0 - PAD, cut + timedelta(seconds=1)), i1 + PAD),
            ("benign", max(i0 - PAD, cut) - timedelta(days=1), i1 + PAD - timedelta(days=1)),
        ]
        short = host.split(".")[1]
        for kind, a, b in windows:
            wid = f"{short}_{kind}"
            w = build_window(host, wid, kind, a, b, recs, suricata, burst)
            path = os.path.join(args.out, f"{wid}.json")
            with open(path, "w") as f:
                json.dump(w, f, indent=1)
            g = w["ground_truth"]
            index.append({"window_id": wid, "file": os.path.basename(path), "host": host,
                          "kind": kind, "start": w["start"], "end": w["end"],
                          "n_lines": g["n_lines"], "n_malicious": g["n_malicious"],
                          "n_side_effect": g["n_side_effect"],
                          "phases_present": g["phases_present"],
                          "suricata_alerts": w["suricata_baseline"]["n_alerts"]})
            print(f"{wid:18s} {w['start'][5:]} -> {w['end'][11:]}  lines={g['n_lines']:6d} "
                  f"malicious={g['n_malicious']:6d}  side_effect={g['n_side_effect']:5d}  suricata={w['suricata_baseline']['n_alerts']:5d}  "
                  f"phases={','.join(g['phases_present'])}")
    with open(os.path.join(args.out, "index.json"), "w") as f:
        json.dump(index, f, indent=1)


if __name__ == "__main__":
    main()
