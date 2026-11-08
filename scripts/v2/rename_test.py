"""Memorization check for Setting C: does the LLM recognize the public AIT data sets?

1. probe   ask the models, without any alert, what they know about the data sets and their attacker
           addresses and domains (no evidence is given).
2. rename  triage a stratified sample of cases with every identifying name replaced consistently per
           scenario: IP addresses (kept within their private/public range), the company and scenario
           domain words, the mail-server host names, and the attacker's exfiltration domain. The verdicts
           are compared with the original prompts (run 1) and with the run-to-run agreement of Haiku.

Usage: .venv/bin/python scripts/v2/rename_test.py probe|rename|report [--model M] [--conditions ...]
Output: outputs/probeC_<model>.jsonl, outputs/renameC_<model>.jsonl, results/rename_test.md
"""
import argparse
import glob
import json
import os
import random
import re
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
from triage import ask, parse_verdict  # noqa: E402
from triage_v2 import CONDITIONS, SYSTEM, build_prompt, load_cases  # noqa: E402

BASE = os.path.join(HERE, "..", "..")
IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
KEEP_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "127.0.0.1", "0.0.0.0", "255.255.255.255"}
FAKE = ["kestrel", "marlow", "fenwick", "osgood", "talbot", "quill", "brandt", "corwin", "delacy", "ember",
        "faraday", "gilroy", "hollis", "ingram", "jarvis", "keswick", "lowry", "mercer", "norwood", "orrin",
        "pembrook", "radley", "sutton", "thorne", "upton", "varga", "whitlow", "yardley", "zeller", "ashby"]
N_MAL, N_BEN = 50, 50

PROBES = [
    "What do you know about the AIT Log Data Set V2.0 and the AIT Alert Data Set (AIT-ADS) from the Austrian "
    "Institute of Technology? Name the scenarios, the attacker IP addresses, and the domains used for DNS exfiltration, "
    "if you know them.",
    "In the AIT Log Data Set V2.0 scenario 'wheeler' (company domain flores.wheeler.biz), which IP address does the "
    "attacker use, and at what times do the attack steps happen? Answer with specifics if you know them, otherwise say so.",
    "In the AIT Log Data Set V2.0 scenario 'harrison', which internal host exfiltrates data over DNS, and to which "
    "domain? Answer with specifics if you know them, otherwise say so.",
]


def scen_terms(scen, cases):
    """Identifying words of a scenario: scenario name, company words, mail host prefixes, exfiltration domains."""
    words = {scen}
    for c in cases:
        for e in c["examples"]:
            words |= {m for m in re.findall(r"\b([a-z0-9]+)\.%s\.[a-z]+" % scen, e)}
        if c["host"] and c["host"].endswith("-mail"):
            words.add(c["host"][:-5])
    exfil = set()
    for l in open(os.path.join(BASE, "alerts_v2", f"{scen}.jsonl")):
        a = json.loads(l)
        if a.get("eve") and any(x.startswith("dnsteal") for x in a["labels"]):
            m = re.search(r"\.([a-z0-9-]+)\.(biz|com|org|info|net)\b", a["eve"])
            if m:
                exfil.add(m.group(1))
    return sorted(words | exfil, key=len, reverse=True)


class Renamer:
    def __init__(self, scen, cases, seed):
        rng = random.Random(seed)
        fakes = FAKE[:]
        rng.shuffle(fakes)
        self.words = {w: fakes[i % len(fakes)] + ("" if i < len(fakes) else str(i)) for i, w in enumerate(scen_terms(scen, cases))}
        self.ips, self.rng = {}, rng

    def ip(self, m):
        ip = m.group(0)
        if ip in KEEP_IPS or ip.startswith(("127.", "0.", "255.")):
            return ip
        if ip not in self.ips:
            a, b = int(m.group(1)), int(m.group(2))
            r = self.rng.randint
            if a == 10:
                new = f"10.{r(0, 255)}.{r(0, 255)}.{r(1, 254)}"
            elif a == 172 and 16 <= b <= 31:
                new = f"172.{r(16, 31)}.{r(0, 255)}.{r(1, 254)}"
            elif a == 192 and b == 168:
                new = f"192.168.{r(0, 255)}.{r(1, 254)}"
            else:
                new = f"{self.rng.choice([23, 34, 45, 52, 64, 81, 95, 104, 141, 185])}.{r(0, 255)}.{r(0, 255)}.{r(1, 254)}"
            self.ips[ip] = new
        return self.ips[ip]

    def __call__(self, text):
        text = IP_RE.sub(self.ip, text)
        for w, f in self.words.items():
            text = re.sub(r"(?i)(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(w), f, text)
        return text


def sample(cases):
    import analyze_C as C
    rng = random.Random(11)
    ids = sorted(C.SAMPLE)
    mal = [c for c in ids if cases[c]["truth"]]
    ben = [c for c in ids if not cases[c]["truth"]]
    return rng.sample(mal, N_MAL) + rng.sample(ben, N_BEN)


def run_rename(args):
    cases = load_cases()
    ids = sample(cases)
    by_scen = {}
    for c in cases.values():
        by_scen.setdefault(c["scenario"], []).append(c)
    ren = {s: Renamer(s, by_scen[s], i) for i, s in enumerate(sorted(by_scen))}
    out_path = os.path.join(BASE, "outputs", f"renameC_{args.model}.jsonl")
    done = {(r["case_id"], r["condition"]) for r in map(json.loads, open(out_path))} if os.path.exists(out_path) else set()
    jobs = [(c, k) for c in ids for k in args.conditions if (c, k) not in done]
    print(f"{len(jobs)} calls -> {out_path}")

    def one(job):
        c, k = job
        case = cases[c]
        prompt = ren[case["scenario"]](build_prompt(case, CONDITIONS[k], {}))
        text, stop, tin, tout = ask(args.model, prompt, "medium", system=SYSTEM)
        v = parse_verdict(text)
        return {"case_id": c, "condition": k, "truth": case["truth"], "verdict": v["verdict"] if v else None,
                "reason": v.get("reason") if v else None, "prompt_tokens": tin, "output_tokens": tout,
                "prompt": prompt if args.keep_prompts else None}

    with open(out_path, "a") as f, ThreadPoolExecutor(8) as pool:
        for rec in pool.map(one, jobs):
            f.write(json.dumps(rec) + "\n")
            f.flush()


def run_probe(args):
    out_path = os.path.join(BASE, "outputs", f"probeC_{args.model}.jsonl")
    with open(out_path, "w") as f:
        for q in PROBES:
            text, stop, tin, tout = ask(args.model, q, "medium", system="You are a helpful assistant.")
            f.write(json.dumps({"question": q, "answer": text, "prompt_tokens": tin, "output_tokens": tout}) + "\n")
            print("Q:", q, "\nA:", text, "\n")


def report():
    cases = load_cases()
    ids = set(sample(cases))
    said = lambda r: (r["verdict"] or "malicious") == "malicious"
    L = ["# Memorization check (Setting C): original vs. renamed prompts", "",
         f"Sample: {N_MAL} malicious + {N_BEN} benign cases. Agreement = share of cases with the same verdict.", "",
         "| model | condition | detected orig. / renamed | false alarms orig. / renamed | agreement orig. vs renamed | agreement run 1 vs run 2 |",
         "|---|---|---|---|---|---|"]
    for p in sorted(glob.glob(os.path.join(BASE, "outputs", "renameC_*.jsonl"))):
        model = os.path.basename(p)[len("renameC_"):-6]
        ren = {(r["case_id"], r["condition"]): r for r in map(json.loads, open(p))}
        orig, run2 = {}, {}
        for path, d in [(os.path.join(BASE, "outputs", f"triageC_{model}.jsonl"), orig),
                        (os.path.join(BASE, "outputs", f"triageC_{model}_run2.jsonl"), run2)]:
            if os.path.exists(path):
                for r in map(json.loads, open(path)):
                    if r["case_id"] in ids:
                        d[(r["case_id"], r["condition"])] = r
        for k in CONDITIONS:
            keys = [x for x in ren if x[1] == k and x in orig]
            if not keys:
                continue
            det = lambda d: sum(said(d[x]) for x in keys if cases[x[0]]["truth"])
            fa = lambda d: sum(said(d[x]) for x in keys if not cases[x[0]]["truth"])
            agree = 100 * sum(said(ren[x]) == said(orig[x]) for x in keys) / len(keys)
            a2 = [x for x in keys if x in run2]
            agree2 = f"{100 * sum(said(run2[x]) == said(orig[x]) for x in a2) / len(a2):.0f}%" if a2 else "-"
            L.append(f"| {model} | {k} | {det(orig)} / {det(ren)} | {fa(orig)} / {fa(ren)} | {agree:.0f}% | {agree2} |")
    open(os.path.join(BASE, "results", "rename_test.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["probe", "rename", "report", "preview"])
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--conditions", nargs="*", default=["L0_none", "only_ip", "L4_+host"])
    ap.add_argument("--keep-prompts", action="store_true")
    a = ap.parse_args()
    if a.what == "probe":
        run_probe(a)
    elif a.what == "rename":
        run_rename(a)
    elif a.what == "preview":
        cases = load_cases()
        c = cases[[i for i in sample(cases) if cases[i]["why"].get("dns_line")][0]]
        allc = [x for x in cases.values() if x["scenario"] == c["scenario"]]
        r = Renamer(c["scenario"], allc, 0)
        print(r.words)
        print(r(build_prompt(c, CONDITIONS["L4_+host"], {})))
    else:
        report()
