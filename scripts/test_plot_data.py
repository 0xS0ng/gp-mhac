"""Regression checks for confidence intervals and the published sampling grids."""
from pathlib import Path
import unittest
from plot_data import local_cells, network_cells, summarize


class SampleTests(unittest.TestCase):
    def test_paired_interval_uses_covariance(self):
        first={i:float(1+i) for i in range(100)}
        second={i:float(100-i) for i in range(100)}
        cell=summarize(first,"ms",second)
        self.assertGreater(cell.half,0)
        self.assertEqual(cell.stacked_half,0)
        self.assertEqual(cell.mean,50.5)

    def test_incomplete_grid_rejected(self):
        with self.assertRaisesRegex(ValueError,"100 distinct"):
            summarize({i:1. for i in range(99)},"ms")

    def test_noninteger_or_varying_sizes_rejected(self):
        vals={i:336. for i in range(100)}
        vals[60]=335.
        with self.assertRaisesRegex(ValueError,"deterministic"):
            summarize(vals,"B")
        with self.assertRaisesRegex(ValueError,"integer"):
            summarize(dict.fromkeys(range(100),336.5),"B")

    def test_local_latency_shared_between_panels(self):
        cells=network_cells(Path(__file__).resolve().parents[1]/"results")
        local={k[1:]:c for k,c in cells.items() if k[0]=="e2e"}
        same={k[1:]:c for k,c in cells.items() if k[0]=="network" and k[2]=="LOCAL"}
        self.assertEqual(len(local),12)
        self.assertEqual(same,local)

    def test_canonical_share_sizes(self):
        cells=local_cells(Path(__file__).resolve().parents[1]/"results")
        for name,num in (("gp-mhac",336),("mhac",304),("tz23",80)):
            for holders in (6,10,20,40,70,100):
                row=cells["sizes",name,"storage",str(holders)]
                self.assertEqual((row.mean,row.half,row.unit),(num,0.,"B"))


if __name__=="__main__":
    unittest.main()
