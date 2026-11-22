"""Read primitive timings, holder storage, broadcast sizes and analytical counters."""

import argparse
import csv
from collections import defaultdict
from itertools import product
from math import isclose, isfinite, sqrt
from pathlib import Path
from statistics import fmean, stdev

OPERATIONS = ("E1", "E2", "P", "H_G", "V_sig", "SHA256", "H_field")
HOLDERS = (6, 10, 20, 40, 70, 100)
COUNT_FILES = ("gp_ops.csv", "mhac_tz_ops.csv", "gp_bytes.csv", "mhac_tz_lengths.csv")


def read(path):
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def primitives(rows):
    """Return mean and 95% Student-t half-width in microseconds per invocation."""
    if len(rows) != 1100 * len(OPERATIONS):
        raise ValueError("expected 100 warm-up and 1000 timed blocks of seven operations")
    times = defaultdict(list)
    for block in range(1100):
        seen = set()
        for position, row in enumerate(rows[block * 7 : (block + 1) * 7]):
            op = row["operation"]
            calls = 32 if op in ("SHA256", "H_field") else 1
            elapsed = int(row["elapsed_ns"])
            value = elapsed / 1000 / calls
            if not (
                op in OPERATIONS and op not in seen and int(row["position"]) == position
                and int(row["block"]) == block and int(row["calls"]) == calls and elapsed > 0
                and row["phase"] == ("warmup" if block < 100 else "measured")
                and isclose(float(row["us_per_call"]), value, rel_tol=1e-12, abs_tol=1e-6)
            ):
                raise ValueError(f"invalid timing at block {block}, position {position}")
            seen.add(op)
            if block >= 100:
                times[op].append(value)
    return [(op, fmean(times[op]), 1.96234146113345 * stdev(times[op]) / sqrt(1000))
            for op in OPERATIONS]


def sizes(rows):
    """Return the deterministic compressed byte length of each complete cell."""
    values = defaultdict(dict)
    for row in rows:
        key = row["scheme"], row["series"], int(row["x"])
        sample, value = int(row["sample"]), float(row["value"])
        if (row["experiment"] != "sizes" or row["unit"] not in ("B", "bytes")
                or not isfinite(value) or not value.is_integer() or value <= 0
                or sample not in range(100) or sample in values[key]):
            raise ValueError(f"invalid size observation for {key}")
        values[key][sample] = int(value)
    expected = set(product(("gp-mhac", "mhac"), ("storage", "private2", "private4"), HOLDERS))
    expected.update(("tz23", "storage", n) for n in HOLDERS)
    if set(values) != expected:
        raise ValueError("incomplete or unexpected storage and communication grid")
    result = []
    for key, samples in sorted(values.items()):
        if len(samples) != 100 or len(set(samples.values())) != 1:
            raise ValueError(f"nonconstant or incomplete byte length for {key}")
        result.append((*key, samples[0]))
    return result


def check_formulas(rows):
    """Compare each predicted integer field with its independent counted or encoded field."""
    if not rows:
        raise ValueError("empty cost table")
    pairs = []
    for col in rows[0]:
        if col.startswith("expected_"):
            suffix = col.removeprefix("expected_")
            measured = suffix if suffix in rows[0] else "actual_" + suffix
            if measured not in rows[0]:
                raise ValueError(f"missing counter for {col}")
            pairs.append((measured, col))
    if not pairs:
        raise ValueError("no predicted fields in cost table")
    for i, row in enumerate(rows, 2):
        for measured, expected in pairs:
            if int(row[measured]) != int(row[expected]):
                raise ValueError(f"row {i}: {measured}={row[measured]} != {row[expected]}")
    return len(rows) * len(pairs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("results"))
    root = parser.parse_args().results
    print("Primitive | mean (µs) | 95% half-width (µs)\n---|---:|---:")
    for op, mean, ci in primitives(read(root / "primitives.csv")):
        print(f"{op} | {mean:.8g} | {ci:.8g}")
    print("\nScheme | metric | holders | bytes\n---|---|---:|---:")
    for scheme, series, n, value in sizes(read(root / "sizes.csv")):
        print(f"{scheme} | {series} | {n} | {value}")
    print("\nAnalytical cost table | matching integer checks\n---|---:")
    for name in COUNT_FILES:
        print(f"{name} | {check_formulas(read(root / name))}")


if __name__ == "__main__":
    main()
