"""Draw the eight paper figures from individual observations, without timing any protocol."""
import argparse
import csv
import os
from pathlib import Path

os.environ.setdefault("MPLBACKEND", "Agg")
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.container import BarContainer, ErrorbarContainer
import numpy as np

import plot_lines
import plot_bars

PANELS = {
    "comp_role": ("5a","lines"), "comp_e2e": ("5b","bars"),
    "comp_verify": ("6a","bars"), "comp_detection": ("6b","bars"),
    "comp_access": ("7a","bars"), "comp_policy": ("7b","bars"),
    "communication_cost": ("8a","lines"), "network_latency": ("8b","lines"),
}
W, H = 123.431492, 100  # Individual panels in big points (1/72 inch).


def check_marks(key, ax, records):
    """Check each data series and its whiskers against the physical marks."""
    values = [r for r in records if r.get("kind") != "annotation_range"]
    bars = PANELS[key][1] == "bars"
    deterministic = key == "communication_cost"
    errors = [c for c in ax.containers if isinstance(c, ErrorbarContainer)]
    groups = [str(x) for x in values[0]["x"]]
    if any([str(x) for x in row["x"]] != groups for row in values):
        raise ValueError(f"{key}: series use different sampling grids")
    if bars:
        # Within a category the documented series order is the left-to-right bar order.
        ticks = ax.get_xticks()
        if [t.get_text() for t in ax.get_xticklabels()] != groups:
            raise ValueError(f"{key}: unexpected category labels or order")
        patches = [p for c in ax.containers if isinstance(c, BarContainer) for p in c]
        positions = [[] for _ in groups]
        for p in patches:
            x = p.get_x() + p.get_width()/2
            j = int(np.argmin(np.abs(ticks - x)))
            if p.get_y() != 0 or abs(ticks[j]-x) >= .5:
                raise ValueError(f"{key}: unexpected bar base or categorical position")
            positions[j].append((x, p.get_height()))
        for group in positions:
            group.sort()
            if len(group) != len(values) or len({x for x,_ in group}) != len(values):
                raise ValueError(f"{key}: missing, repeated or misplaced bar")
        xy = [list(series) for series in zip(*positions)]
    else:
        lines = ax.lines if deterministic else [c.lines[0] for c in errors]
        xy = [list(zip(l.get_xdata(), l.get_ydata())) for l in lines]
    if len(xy) != len(values):
        raise ValueError(f"{key}: wrong number of plotted series")

    # Match intervals to actual center positions. For intersecting lines, use the
    # error-bar container's series order, not just the common x coordinate.
    target_errors = []
    lo, hi = ax.get_ylim()
    for line, row in zip(xy, values):
        if len(line) != len(groups):
            raise ValueError(f"{key}: missing plotted center")
        for (px, py), x, y, h in zip(line, row["x"], row["y"], row["ci"]):
            if not np.isclose(py,y,rtol=2e-13,atol=2e-13) or (not bars and px != x):
                raise ValueError(f"{key}: center differs for {row['label']} at {x}")
            if y-h < lo or y+h > hi:
                raise ValueError(f"{key}: interval outside plotting area")
            if not deterministic:
                target_errors.append((px, y-h, px, y+h))
    actual_errors = [(a[0],a[1],b[0],b[1]) for c in errors for col in c.lines[2]
                     for a,b in col.get_segments()]
    if bars:
        actual_errors.sort()
        target_errors.sort()
    if len(target_errors) != len(actual_errors) or not np.allclose(
            actual_errors, target_errors, rtol=2e-13, atol=2e-13):
        raise ValueError(f"{key}: drawn intervals differ from the source values")
    return sum(map(len,xy)), len(actual_errors)


def draw(results, dest, points=None):
    """Write the panel PDFs and optionally the source values used by each artist."""
    results, dest = Path(results), Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    face = "Times New Roman"
    try:
        for style in ("normal","italic"):
            font_manager.findfont(font_manager.FontProperties(family=face,style=style),fallback_to_default=False)
    except ValueError:
        face = "STIXGeneral"  # Bundled Times-style face where Times New Roman is unavailable.
    mpl.rcParams.update({
        "font.family":face, "font.serif":[face], "font.size":7, "axes.labelsize":7,
        "mathtext.fontset":"custom", "mathtext.rm":face, "mathtext.it":face+":italic",
        "mathtext.bf":face+":bold", "mathtext.cal":face+":italic",
        "mathtext.sf":face, "mathtext.tt":face, "mathtext.fallback":None,
        "axes.labelpad":1, "axes.linewidth":.50, "axes.unicode_minus":True, "xtick.labelsize":7,
        "ytick.labelsize":7, "xtick.major.size":2, "ytick.major.size":2, "xtick.major.width":.5,
        "ytick.major.width":.5, "xtick.major.pad":1.2, "ytick.major.pad":1.1,
        "legend.fontsize":6, "legend.frameon":False, "lines.linewidth":.8, "lines.markersize":2.5,
        "hatch.linewidth":.35, "pdf.fonttype":42, "ps.fonttype":42,
        "savefig.bbox":None, "figure.autolayout":False, "axes.formatter.useoffset":False,
    })
    source=[]
    stats=[]
    for key,(number,kind) in PANELS.items():
        fig, ax = plt.subplots(figsize=(W/72,H/72),dpi=144)
        fig.subplots_adjust(left=.211,right=.989,bottom=.222,top=.976)
        ax.set_axisbelow(True)
        ax.grid(True, which="major", axis="both", linestyle=(0,(1.0,1.9)),
                linewidth=.32, color="#b6b6b6")
        ax.tick_params(axis="both",direction="in",top=True,right=True,
                       length=1.7,width=.45)
        render = (plot_lines.comparison if key in ("comp_e2e", "comp_verify") else
                  plot_lines.draw if kind == "lines" else plot_bars.draw)
        series=render(key,fig,ax,results)
        lo,hi=ax.get_ylim()
        highest=max(y+h for s in series if s.get("kind") != "annotation_range"
                    for y,h in zip(s["y"],s["ci"]))
        if highest>hi:  # Allow the same panels to accommodate timings from other machines.
            ax.set_ylim(lo,highest*1.2)
        n,e=check_marks(key,ax,series)
        stats.append((key,n,e))
        for s in series:
            for x,y,h in zip(s["x"],s["y"],s["ci"]):
                role=s.get("kind","series")
                source.append(dict(panel=number,file=key+".pdf",series=s["label"],x=x,
                                   mean=y,ci95_half=h,unit="KiB" if key=="communication_cost" else "ms",
                                   role=role,mark_or_ci_note=(
                                       "range note only" if role=="annotation_range" else
                                       "deterministic; no whisker" if key=="communication_cost" else "mean and 95% CI")))
        fig.savefig(dest/(key+".pdf"),format="pdf",
                    metadata={"CreationDate":None,"ModDate":None,"Title":f"GP-MHAC | {number}"})
        plt.close(fig)
    if points:
        with Path(points).open("w",newline="",encoding="utf-8") as fh:
            writer=csv.DictWriter(fh,fieldnames=source[0],lineterminator="\n")
            writer.writeheader()
            writer.writerows(source)
    return stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("results"))
    parser.add_argument("--output", type=Path, default=Path("figures"))
    parser.add_argument("--points", type=Path, help="optional per-series means, intervals and units as CSV")
    args=parser.parse_args()
    stats=draw(args.results,args.output,args.points)
    for name,n,e in stats:
        print(f"{name}: {n} marks, {e} confidence intervals")


if __name__=="__main__":
    main()
