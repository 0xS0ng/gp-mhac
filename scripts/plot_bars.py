"""Draw grouped protocol cost and detection bars."""
from pathlib import Path
from matplotlib.patches import Patch
from plot_data import local_cells as _cells

SCHEMES = {"gp-mhac": ("GP-MHAC", "#4477AA"), "mhac": ("MHAC", "#EE6677")}
CASES = tuple("ABCDEF")
PHASES = (
    ("iss", "CredIss", "#08519C"),
    ("end_to_end", "CredPres", "#EE6677"),
    ("detect_total", "Detection", "#6BAED6"),
)


def _entry(label, x, y, ci, **meta):
    return dict(label=label, x=list(x), y=list(y), ci=list(ci), **meta)


def _patch(color, hatch="", edge="#404040"):
    return Patch(facecolor=color, edgecolor=edge, linewidth=.3, hatch=hatch)


def _bar(ax, pos, value, width, color, hatch="", base=0., edge="black"):
    ax.bar(pos, value, width, bottom=base, color=color, hatch=hatch,
           edgecolor=edge, linewidth=.24, zorder=2)


def _whisker(ax, pos, height, half, cap=.60):
    ax.errorbar(pos, height, yerr=half, fmt="none", ecolor="#242424",
                elinewidth=.42, capsize=cap, capthick=.40, zorder=3)


def draw(key, fig, ax, repo):
    from plot_bar_groups import detection, policy
    from plot_access import access
    return {"comp_detection":detection, "comp_access":access, "comp_policy":policy}[key](fig,ax,Path(repo))
