"""Read the public sample files and compute two-sided 95% Student-t intervals."""

import csv
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from math import isfinite, sqrt
from statistics import fmean, stdev

HOLDERS = (6, 10, 20, 40, 70, 100)
ATTRIBUTES = (8, 16, 24, 32, 48, 64)
SCHEMES = ('gp-mhac','mhac')
REPETITIONS = 100
T_CRITICAL = 1.9842169515086827  # 0.975 quantile for 99 degrees of freedom.


@dataclass(frozen=True)
class Cell:
    mean: float
    half: float
    unit: str
    stacked_half: float | None = None


def summarize(samples, unit, paired=None):
    """Summarize a complete sample; optionally pair two stages by repetition."""
    if set(samples) != set(range(REPETITIONS)):
        raise ValueError("a cell must contain 100 distinct numbered samples")
    vals = [samples[i] for i in range(REPETITIONS)]
    if not all(isfinite(v) and v > 0 for v in vals):
        raise ValueError("measurements must be finite and positive")
    if unit == 'B' and (len(set(vals)) != 1 or not vals[0].is_integer()):
        raise ValueError("serialized length must be a deterministic integer")
    half = lambda xs: T_CRITICAL * stdev(xs) / sqrt(REPETITIONS)
    joint = half([samples[i]+paired[i] for i in range(REPETITIONS)]) if paired is not None else None
    return Cell(fmean(vals), half(vals), unit, joint)


def rows(path):
    """Return the records in the CSV at path, preserving their stored order."""
    with path.open(encoding='utf-8', newline='') as fh:
        return list(csv.DictReader(fh))


def insert(bucket, key, rep, val):
    if rep in bucket[key]:
        raise ValueError(f"duplicate repetition {rep} in {key}")
    bucket[key][rep] = val


@lru_cache(maxsize=2)
def local_cells(results):
    """Return measurements and paired presentation/detection uncertainty by setting."""
    samples = defaultdict(dict)
    for exp in ('roles','verify','access','policy','detection','sizes'):
        units = ('bytes','B') if exp == 'sizes' else ('ms',)
        for r in rows(results / (exp+'.csv')):
            if r['experiment'] != exp or r['scheme'] not in (*SCHEMES,'tz23') or r['unit'] not in units:
                raise ValueError(f"unexpected sample label in {exp}.csv: {r}")
            key=(exp,r['scheme'],r['series'],r['x'])
            insert(samples,key,int(r['sample']),float(r['value']))
    cells = {}
    for key, values in samples.items():
        exp,s,metric,x=key
        paired=samples['access',s,'end_to_end',x] if (exp,metric)==('access','detect_total') else None
        cells[key]=summarize(values,'B' if exp=='sizes' else 'ms',paired)
    return cells


@lru_cache(maxsize=2)
def network_cells(results):
    """Use matched local, LAN and WAN runs; reject an unrelated local latency file."""
    all_rows=rows(results/'network.csv')
    local=rows(results/'e2e.csv')
    if local != [r for r in all_rows if r['condition']=='LOCAL']:
        raise ValueError("e2e.csv must be the LOCAL rows from the same interleaved batch")
    output={}
    for exp,records,conditions in (('e2e',local,('LOCAL',)),('network',all_rows,('LOCAL','LAN','WAN'))):
        samples=defaultdict(dict)
        expected={(exp,s,c,str(n)) for s in SCHEMES for c in conditions for n in HOLDERS}
        for r in records:
            key=(exp,r['scheme'],r['condition'],r['n'])
            if key not in expected: raise ValueError(f"unexpected network cell: {key}")
            if r['phase']=='warmup': continue
            if r['phase']!='measured': raise ValueError(f"unexpected timing phase: {r['phase']}")
            insert(samples,key,int(r['sample']),float(r['elapsed_ms']))
        if set(samples)!=expected: raise ValueError(f"incomplete {exp} grid")
        output.update({key:summarize(v,'ms') for key,v in samples.items()})
    return output
