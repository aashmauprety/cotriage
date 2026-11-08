"""Price-independent cost reporting: mean input/output tokens per alert, Settings A and C.

For every model and configuration (no tools, single tools, all tools, learned routing P2 with lambda=0.05) the
mean number of input and output tokens per alert, mean over runs. Output tokens include the model's reasoning
tokens, which are billed as output. Also: the cost of P2 and of all tools relative to no tools when the ratio of
output to input price changes (1, 3, 5 = our three price lists, 8), with the tool sets that P2 chose at our prices.

Usage: .venv/bin/python scripts/token_counts.py  ->  results/token_counts.md
"""
import os
import sys
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from routing_baselines import Setting, err, P  # noqa: E402

LAM = 0.05
RATIOS = [1, 3, 5, 8]
SHOW = {"A": ["L0_none", "only_suricata", "only_ip", "only_audit", "L4_+audit"],
        "C": ["L0_none", "only_context", "only_ip", "only_host", "L4_+host"]}


def p2_tokens(S, m, r):
    """(input, output) tokens of every test alert under P2, leave-one-fold-out as in the paper."""
    conds = S.conds(m, r)
    out = []
    for test in sorted({S.fold(c) for c in r}):
        train = [c for c in r if S.fold(c) != test]
        base = sum(S.cost(m, r[c]["L0_none"]) for c in train) / len(train)
        by = defaultdict(list)
        for c in train:
            by[S.sig(c)].append(c)
        sig = {s: min(conds, key=lambda k: sum(err(S, r, c, k) + LAM * S.cost(m, r[c][k]) / base for c in cs))
               for s, cs in by.items()}
        for c in r:
            if S.fold(c) == test:
                x = r[c][sig.get(S.sig(c), "only_ip")]
                out.append((x["prompt_tokens"], x["output_tokens"]))
    return out


def main():
    L = ["# Tokens per alert (price-independent cost)", "",
         "Mean over cases and runs. Output tokens include reasoning tokens. P2 = learned routing, lambda=0.05.", ""]
    L2 = ["## Cost relative to no tools for other output/input price ratios", "",
          "Same decisions (P2 tool sets chosen at our prices); only the price ratio changes.", "",
          "| setting | model | config | " + " | ".join(f"ratio {q}" for q in RATIOS) + " |",
          "|---|---|---|" + "---|" * len(RATIOS)]
    for name in ["A", "C"]:
        S = Setting(name)
        L += [f"## Setting {name}", "", "| model | configuration | input tokens | output tokens |", "|---|---|---|---|"]
        for m in S.models:
            rs = S.runs(m)
            if not rs:
                continue
            conds = S.conds(m, rs[0])
            toks = {k: [[(r[c][k]["prompt_tokens"], r[c][k]["output_tokens"]) for c in r] for r in rs]
                    for k in SHOW[name] if k in conds}
            toks["P2"] = [p2_tokens(S, m, r) for r in rs]
            mean = {k: (np.mean([np.mean([t[0] for t in run]) for run in v]),
                        np.mean([np.mean([t[1] for t in run]) for run in v])) for k, v in toks.items()}
            for k, (i, o) in mean.items():
                L.append(f"| {S.nm[m]} | {k} | {i:.0f} | {o:.0f} |")
            i0, o0 = mean["L0_none"]
            for k in ["P2", SHOW[name][-1]]:
                if k in mean:
                    i, o = mean[k]
                    L2.append(f"| {name} | {S.nm[m]} | {k} | " + " | ".join(f"{(i + q * o) / (i0 + q * o0):.2f}" for q in RATIOS) + " |")
        L.append("")
    out = os.path.join(P.BASE, "results", "token_counts.md")
    open(out, "w").write("\n".join(L + L2) + "\n")
    print("\n".join(L + L2))


if __name__ == "__main__":
    main()
