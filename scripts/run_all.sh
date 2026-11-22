#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: scripts/run_all.sh [--dry-run] [NEW_DIR]'
}

die() {
    printf '%s\n' "$*" >&2
    exit 2
}

dry_run=false
dest=
for arg in "$@"; do
    case "$arg" in
        --dry-run) dry_run=true ;;
        -h|--help) usage; exit 0 ;;
        -*|'') die "Invalid argument: $arg" ;;
        *) [[ -z $dest ]] || die 'Expected a single output directory.'; dest=$arg ;;
    esac
done
dest=${dest:-out}
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
parent=$(cd -- "$(dirname -- "$dest")" && pwd -P) || die 'The output parent must exist.'
out="$parent/$(basename -- "$dest")"
case "$out" in "$repo/results"|"$repo/results/"*) die 'Choose a directory outside results/.' ;; esac
[[ ! -e $out && ! -L $out ]] || die "Output path already exists: $out"

show() {
    printf '%q' "$1"
    shift
    if (($#)); then printf ' %q' "$@"; fi
}

run() {
    if $dry_run; then show "$@"; printf '\n'; else "$@"; fi
}

cd -- "$repo"
if $dry_run; then show cd "$repo"; printf '\n'; fi
export MPLBACKEND=Agg
run mkdir "$out"
run cargo build --release --bins --locked --target-dir target
run target/release/bench_primitives "$out/primitives.csv"
run target/release/bench_roles "$out/roles.csv"
run target/release/bench_network "$out/latency"
run cp "$out/latency/e2e.csv" "$out/latency/network.csv" "$out/"
run target/release/bench_verify "$out/verify.csv"
run target/release/bench_detection "$out/detection.csv"
run target/release/bench_access "$out/access.csv"
run target/release/bench_policy "$out/policy.csv"
run target/release/bench_sizes "$out/sizes.csv"
run target/release/count_ops "$out"
if $dry_run; then
    show python3 -B scripts/summarize_tables.py --results "$out"
    printf ' > %q\n' "$out/tables.md"
else
    python3 -B scripts/summarize_tables.py --results "$out" > "$out/tables.md"
fi
run python3 -B scripts/plot_figures.py --results "$out" --output "$out/figures"
