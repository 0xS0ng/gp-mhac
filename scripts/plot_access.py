"""Compare three protocol stages for six access structures."""
from plot_bars import CASES
from plot_bar_groups import stage_groups


def access(fig, ax, repo):
    return stage_groups(ax, repo, "access", CASES, "Access structure",
                        headroom=30.5)
