import unittest

from summarize_tables import check_formulas, primitives, sizes


class CostTables(unittest.TestCase):
    def test_count_and_byte_fields(self):
        self.assertEqual(check_formulas([{"P": 2, "expected_P": 2,
                                         "actual_bytes": 80, "expected_bytes": 80}]), 2)

    def test_invalid_formulas(self):
        for rows in ([], [{"bytes": 41}], [{"expected_bytes": 41}],
                     [{"bytes": 41, "expected_bytes": 40}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                check_formulas(rows)

    def test_incomplete_workloads(self):
        for function in (primitives, sizes):
            with self.subTest(function=function.__name__), self.assertRaises(ValueError):
                function([])


if __name__ == "__main__":
    unittest.main()
