"""Setting C: confidence of the model on missed attacks versus benign alerts.

For each alert, the confidence is averaged over the runs. Missed attacks are attacks the model dismissed in
every run; benign alerts are all benign alerts of the sample. A confidence band that escalates the missed
attacks therefore also escalates benign alerts when the two medians are close.

Usage: python scripts/v2/confidence_C.py  ->  results/confidence_C.md
"""
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
sys.argv = sys.argv[:1]
import analyze_C as A  # noqa: E402

MODELS = ["claude-haiku-5-5", "claude-opus-5-5"]  # Gemini models report confidence in their verdict, not P(malicious)
CONDS = ["L0_none", "L4_+host"]


def conf(r):
    return r["confidence"] if r["confidence"] is not None else 0.0


def main():
    L = ["# Setting C: confidence on missed attacks and benign alerts", "",
         "Confidence that the alert is malicious, averaged per alert over the runs. Missed = attack dismissed in every run.", "",
         "| model | configuration | runs | missed attacks | median confidence (missed) | IQR (missed) | benign alerts | median confidence (benign) | IQR (benign) |",
         "|---|---|---|---|---|---|---|---|---|"]
    for m in MODELS:
        rs = A.runs(m, set(A.SAMPLE))
        if not rs:
            continue
        for k in CONDS:
            if not all(k in rs[0][c] for c in A.SAMPLE):
                continue
            att = [c for c in A.SAMPLE if rs[0][c][k]["truth"] and all(not A.said(r[c][k]) for r in rs)]
            ben = [c for c in A.SAMPLE if not rs[0][c][k]["truth"]]
            ma = [np.mean([conf(r[c][k]) for r in rs]) for c in att]
            mb = [np.mean([conf(r[c][k]) for r in rs]) for c in ben]
            qa, qb = np.percentile(ma, [25, 75]) if ma else (np.nan, np.nan), np.percentile(mb, [25, 75])
            L.append(f"| {A.NAME[m]} | {k} | {len(rs)} | {len(att)} | {np.median(ma) if ma else float('nan'):.2f} | "
                     f"{qa[0]:.2f}-{qa[1]:.2f} | {len(ben)} | {np.median(mb):.2f} | {qb[0]:.2f}-{qb[1]:.2f} |")
    out = os.path.join(A.BASE, "results", "confidence_C.md")
    open(out, "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
