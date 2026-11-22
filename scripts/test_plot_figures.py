"""Check categorical bars, protocol series, intervals and exported source points."""
import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from matplotlib.collections import PolyCollection
from matplotlib.colors import to_rgba
from matplotlib.container import BarContainer, ErrorbarContainer
from matplotlib.figure import Figure

from plot_figures import draw


class FigureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panels = {}
        results = Path(__file__).resolve().parents[1] / "results"

        def inspect(fig, file, **kwargs):
            ax = fig.axes[0]
            bars = [p for c in ax.containers if isinstance(c, BarContainer) for p in c]
            labels = [t for t in ax.texts if t.get_gid() == "bar-value"]
            key = Path(file).stem
            legend = ax.get_legend()
            cls.panels[key] = {
                "bars": sorted((p.get_x()+p.get_width()/2, p.get_height(), p.get_facecolor(),
                                p.get_hatch(), p.get_edgecolor()) for p in bars),
                "values": sorted((t.xy[0], t.xy[1], t.get_text(), t.get_fontsize(),
                                  t.get_rotation(), to_rgba(t.get_color())) for t in labels),
                "intervals": sorted((seg[0,0], seg[0,1], seg[1,1])
                                    for c in ax.containers if isinstance(c, ErrorbarContainer)
                                    for col in c.lines[2] for seg in col.get_segments()),
                "ticks": [t.get_text() for t in ax.get_xticklabels()],
                "legend": [t.get_text() for t in legend.get_texts()],
                "edges": (ax.get_position().y0, ax.get_position().y1),
                "notes": [t.get_text() for t in ax.texts if t.get_gid()=="compile-note"],
                "fills": sum(isinstance(c, PolyCollection) for c in ax.collections),
            }
            if key in ("comp_access", "comp_policy"):
                cls.panels[key]["swatches"] = {
                    t.get_text(): (p.get_facecolor(), p.get_hatch() or "")
                    for t, p in zip(legend.get_texts(), legend.get_patches())
                }
                cls.panels[key]["outline_widths"] = {p.get_linewidth() for p in bars}
                cls.panels[key]["axis_labels"] = (ax.get_xlabel(), ax.get_ylabel())
                cls.panels[key]["centers"] = list(ax.get_xticks())

        with tempfile.TemporaryDirectory() as tmp, patch.object(Figure, "savefig", inspect):
            out = Path(tmp)
            cls.counts = {k:(n,e) for k,n,e in draw(results, out, out/"points.csv")}
            with (out/"points.csv").open(newline="") as stream:
                cls.points = list(csv.DictReader(stream))

    def test_mark_and_interval_counts(self):
        self.assertEqual(self.counts, {
            "comp_role": (30,30), "comp_e2e": (12,12), "comp_verify": (18,18),
            "comp_detection": (15,15), "comp_access": (18,18), "comp_policy": (15,15),
            "communication_cost": (24,0), "network_latency": (24,24),
        })

    def test_every_bar_has_an_aligned_value_above_its_interval(self):
        for key in ("comp_e2e","comp_verify","comp_detection","comp_access","comp_policy"):
            panel = self.panels[key]
            with self.subTest(key=key):
                bars,values,intervals = (panel[k] for k in ("bars","values","intervals"))
                self.assertEqual(len(bars), self.counts[key][0])
                self.assertEqual(len(values), len(bars))
                self.assertEqual(len(intervals), len(bars))
                for (x,h,_,_,edge),(vx,vy,txt,pt,angle,color),(ix,_,high) in zip(bars,values,intervals):
                    self.assertAlmostEqual(x, vx)
                    self.assertAlmostEqual(x, ix)
                    self.assertAlmostEqual(vy, high)
                    self.assertEqual(float(txt), float(format(h,".3g")))
                    self.assertEqual(len(txt.replace(".","").lstrip("0")),3)
                    self.assertEqual((pt,angle,color,edge),(6,90,to_rgba("black"),to_rgba("black")))

    def test_categories_and_paired_phase_styles(self):
        a, b = self.panels["comp_access"], self.panels["comp_policy"]
        self.assertEqual(a["ticks"], list("ABCDEF"))
        self.assertEqual(b["ticks"], ["4","8","12","16","24"])
        self.assertEqual(a["axis_labels"], ("Access structure", "Time (ms)"))
        self.assertEqual(b["axis_labels"], ("Policy size $d$", "Time (ms)"))
        self.assertEqual(self.panels["comp_e2e"]["ticks"], ["6","10","20","40","70","100"])
        self.assertEqual(self.panels["comp_verify"]["ticks"], ["8","16","24","32","48","64"])
        self.assertEqual(a["edges"], b["edges"])
        self.assertEqual(a["legend"], b["legend"])
        phases = ("CredIss", "CredPres", "Detection")
        colors = list(map(to_rgba, ("#08519C", "#EE6677", "#6BAED6")))
        styles = [(c, "") for c in colors]
        for panel in (a,b):
            self.assertCountEqual(panel["legend"], phases)
            self.assertEqual(panel["swatches"], dict(zip(phases, styles)))
            self.assertEqual(panel["outline_widths"], {.24})
            for center in panel["centers"]:
                local = [(p[2], p[3] or "") for p in panel["bars"]
                         if min(panel["centers"], key=lambda t: abs(t - p[0])) == center]
                self.assertEqual(local, styles)
            self.assertEqual(len(panel["notes"]),1)
            self.assertIn("CompileAccess:",panel["notes"][0])

    def test_scheme_and_detection_path_encoding(self):
        blue, red, green = map(to_rgba, ("#4477AA","#EE6677","#228833"))
        for key, colors in [("comp_e2e",[blue,red]),("comp_verify",[blue,red,green])]:
            panel = self.panels[key]
            self.assertEqual([b[2] for b in panel["bars"]],colors*6)
        panel = self.panels["comp_detection"]
        self.assertEqual([b[2] for b in panel["bars"]],[blue,blue,blue,red,red]*3)
        self.assertEqual([set(b[3] or "") for b in panel["bars"]],
                         [set(),{"."},{"/"},set(),{"/"}]*3)
        self.assertEqual(set(panel["legend"]),{"GP-MHAC","MHAC","Honest","Prefix","Full blame"})

    def test_network_export_and_compile_note_records(self):
        rows = [r for r in self.points if r["panel"]=="8b"]
        self.assertEqual({r["series"] for r in rows},
                         {s+" "+link for s in ("GP-MHAC","MHAC") for link in ("LAN","WAN")})
        self.assertEqual(self.panels["network_latency"]["fills"], 0)
        for number, source in [("7a","access"),("7b","policy")]:
            categories = self.panels["comp_" + source]["ticks"]
            records = [r for r in self.points if r["panel"]==number]
            notes = [r for r in records if r["role"]=="annotation_range"]
            plotted = [r for r in records if r["role"]=="series"]
            self.assertCountEqual([r["x"] for r in notes], categories)
            self.assertEqual({r["series"] for r in notes},{"CompileAccess"})
            microseconds = [1000 * float(r["mean"]) for r in notes]
            self.assertEqual(self.panels["comp_" + source]["notes"],
                             [f"CompileAccess: {min(microseconds):.1f}–{max(microseconds):.1f} µs"])
            self.assertCountEqual([(r["x"], r["series"]) for r in plotted],
                                  [(x, phase) for x in categories
                                   for phase in ("CredIss", "CredPres", "Detection")])
            self.assertEqual(len(records), len(plotted) + len(notes))
            self.assertTrue(all(r["unit"]=="ms" for r in records))
            path = Path(__file__).resolve().parents[1] / "results" / (source + ".csv")
            with path.open(newline="") as stream:
                verification = {r["x"] for r in csv.DictReader(stream) if r["series"] == "verify"}
            self.assertEqual(verification, set(categories))


if __name__ == "__main__":
    unittest.main()
