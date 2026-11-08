"""Paper figures for the tool-ladder study (called by roi_analysis.py).

  figures/fig1_ladder.png    attacks caught and false-alarm rate along the tool ladder,
                             one column per setting, one line per model
  figures/fig2_cost_vs_acc.png  balanced accuracy vs API cost per 1,000 alerts (log scale),
                             every condition, API models only

Colours: first three slots of the reference categorical palette (validated for
all-pairs use with up to three series); every series is also direct-labelled.
"""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
INK, INK_2, GRID = "#0b0b0b", "#52514e", "#e4e3de"
COLORS = {"qwen2.5-14B (local)": "#2a78d6", "Claude Haiku 5.5": "#eb6834", "Claude Opus 5.5": "#1baf7a"}
SHORT = {"qwen2.5-14B (local)": "qwen 14B", "Claude Haiku 5.5": "Haiku 5.5", "Claude Opus 5.5": "Opus 5.5"}
TITLES = {"A": "A: real Suricata alerts", "B30": "B: vague alert, 30-min window",
          "B5": "B: vague alert, 5-min window"}
TICKS = {"A": ["none", "+alert\nhistory", "+other\nalarms", "+IP\nactivity", "+server\nprograms"],
         "B30": ["none", "+overview", "+other\nalarms", "+IP\nactivity", "+server\nprograms"],
         "B5": ["none", "+overview", "+other\nalarms", "+IP\nactivity", "+server\nprograms"]}
SINGLE_LABEL = {"only_suricata": "other alarms only", "only_ip": "IP activity only",
                "only_audit": "server programs only"}


def style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK_2, labelsize=8, length=0)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def label_ends(ax, ends):
    """Direct labels at line ends; series ending at the same value share one label
    (their lines coincide), the rest are nudged apart so they never overlap."""
    merged = []
    for x, y, text, color in sorted(ends, key=lambda e: e[1]):
        if merged and abs(merged[-1][1] - y) < 0.5:
            merged[-1] = (x, y, merged[-1][2] + " = " + text, color)
        else:
            merged.append((x, y, text, color))
    placed = []
    for x, y, text, color in merged:
        while any(abs(y - p) < 7 for p in placed):
            y += 7
        placed.append(y)
        ax.annotate(text, (x, y), xytext=(6, 0), textcoords="offset points", va="center",
                    fontsize=8, color=INK, annotation_clip=False)


def fig_ladder(rows, settings, models, path):
    cols = [s for s in settings if any(r["setting"] == s for r in rows)]
    fig, axes = plt.subplots(2, len(cols), figsize=(4.0 * len(cols), 5.6), sharey="row",
                             gridspec_kw={"height_ratios": [3, 1.4]})
    for j, s in enumerate(cols):
        top, bot = axes[0][j], axes[1][j]
        ends_top, ends_bot = [], []
        for m in models.values():
            pts = sorted((r for r in rows if r["setting"] == s and r["model"] == m and r["step"] is not None),
                         key=lambda r: r["step"])
            if not pts:
                continue
            x = [p["step"] for p in pts]
            rec = [p["recall"] * 100 for p in pts]
            fpr = [p["fpr"] * 100 for p in pts]
            c = COLORS[m]
            top.plot(x, rec, color=c, linewidth=2, marker="o", markersize=6,
                     markeredgecolor="white", markeredgewidth=1.5, zorder=3,
                     linestyle=(0, (4, 2)) if m == "Claude Opus 5.5" else "-")
            if any(p["runs"] > 1 for p in pts):  # run-to-run range as a thin band
                top.fill_between(x, [p["recall_min"] * 100 for p in pts],
                                 [p["recall_max"] * 100 for p in pts], color=c, alpha=0.15, linewidth=0)
            bot.plot(x, fpr, color=c, linewidth=2, marker="o", markersize=5,
                     markeredgecolor="white", markeredgewidth=1.2, zorder=3)
            ends_top.append((x[-1], rec[-1], SHORT[m], c))
            ends_bot.append((x[-1], fpr[-1], SHORT[m], c))
        label_ends(top, ends_top)
        top.set_title(TITLES[s], fontsize=10, color=INK, loc="left")
        top.set_ylim(-3, 105)
        bot.set_ylim(-3, max(45, max((r["fpr"] * 100 for r in rows), default=0) + 5))
        for ax in (top, bot):
            style(ax)
            ax.set_xticks(range(5))
            ax.set_xlim(-0.3, 4.9)
        top.set_xticklabels([])
        bot.set_xticklabels(TICKS[s])
        if j == 0:
            top.set_ylabel("attacks caught (%)", fontsize=9, color=INK_2)
            bot.set_ylabel("false alarms (%)", fontsize=9, color=INK_2)
    # titles and notes live in the paper's caption
    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor="white")
    plt.close(fig)


def fig_cost(rows, settings, models, path):
    api = [m for m in models.values() if not m.startswith("qwen")]
    cols = [s for s in settings if any(r["setting"] == s and r["model"] in api for r in rows)]
    fig, axes = plt.subplots(1, len(cols), figsize=(4.0 * len(cols), 3.8), sharey=True)
    for ax, s in zip(axes, cols):
        for m in api:
            pts = [r for r in rows if r["setting"] == s and r["model"] == m]
            ladder = sorted((p for p in pts if p["step"] is not None), key=lambda p: p["step"])
            singles = [p for p in pts if p["step"] is None]
            c = COLORS[m]
            ax.plot([p["cost_per_1k"] for p in ladder], [p["bal_acc"] * 100 for p in ladder],
                    color=c, linewidth=1.5, marker="o", markersize=6, markeredgecolor="white",
                    markeredgewidth=1.5, zorder=3)
            ax.scatter([p["cost_per_1k"] for p in singles], [p["bal_acc"] * 100 for p in singles],
                       s=40, facecolors="white", edgecolors=c, linewidths=1.5, zorder=3)
            first, last = ladder[0], ladder[-1]
            ax.annotate(f"{SHORT[m]},\nno tools", (first["cost_per_1k"], first["bal_acc"] * 100),
                        xytext=(-6, 0), textcoords="offset points", fontsize=7.5, color=INK,
                        ha="right", va="center")
            ax.annotate(f"{SHORT[m]}, all tools", (last["cost_per_1k"], last["bal_acc"] * 100),
                        xytext=(6, 4), textcoords="offset points", fontsize=7.5, color=INK)
            worst = min(singles, key=lambda p: p["bal_acc"], default=None)
            if worst:
                ax.annotate(SINGLE_LABEL.get(worst["condition"], worst["condition"]),
                            (worst["cost_per_1k"], worst["bal_acc"] * 100),
                            xytext=(6, -2), textcoords="offset points", fontsize=7, color=INK_2)
        style(ax)
        ax.grid(axis="x", color=GRID, linewidth=0.8)
        ax.set_xscale("log")
        ax.set_xlim(0.05, 60)
        ax.set_ylim(44, 102)
        ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"${v:g}"))
        ax.set_title(TITLES[s], fontsize=10, color=INK, loc="left")
        ax.set_xlabel("API cost per 1,000 alerts ($, log scale)", fontsize=8.5, color=INK_2)
    axes[0].set_ylabel("balanced accuracy (%)", fontsize=9, color=INK_2)
    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor="white")
    plt.close(fig)


def make(rows, settings, models):
    os.makedirs(os.path.join(BASE, "figures"), exist_ok=True)
    fig_ladder(rows, settings, models, os.path.join(BASE, "figures", "fig1_ladder.png"))
    fig_cost(rows, settings, models, os.path.join(BASE, "figures", "fig2_cost_vs_acc.png"))
    print("figures -> figures/fig1_ladder.png, figures/fig2_cost_vs_acc.png")
