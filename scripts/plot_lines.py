"""Draw scheme comparisons, per-role costs, communication and network latency."""
from pathlib import Path
from plot_data import local_cells, network_cells

from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from matplotlib import rcParams

COLORS = {'gp-mhac':'#4477AA', 'mhac':'#EE6677', 'tz23':'#228833'}
NAMES = {'gp-mhac':'GP-MHAC', 'mhac':'MHAC', 'tz23':'TZ23'}
NS = (6, 10, 20, 40, 70, 100)
ATTRIBUTES = (8, 16, 24, 32, 48, 64)


def _series(repo, experiment, scheme, series, xs, label, unit='ms'):
    cells = network_cells(repo) if experiment in ('e2e','network') else local_cells(repo)
    values = [cells[experiment,scheme,series,str(x)] for x in xs]
    if any(c.unit != unit for c in values):
        raise ValueError(f"wrong unit for {scheme} {series}")
    scale=1024 if unit=='B' else 1
    return dict(label=label, x=list(xs), y=[c.mean/scale for c in values],
                ci=[c.half/scale for c in values])


def _line(ax, row, scheme, marker, ls, *, deterministic=False, hollow=False,
          zorder=3, ms=2.5):
    color=COLORS[scheme]
    style=dict(color=color, ls=ls, lw=.8, marker=marker, ms=ms, mew=.60,
               mfc='white' if hollow else color, mec=color, zorder=zorder)
    if deterministic:
        assert not any(row['ci'])
        ax.plot(row['x'],row['y'],**style)
    else:
        ax.errorbar(row['x'],row['y'],yerr=row['ci'],capsize=1.,
                    capthick=.45,elinewidth=.48,**style)


def _key(label,color='0.20',marker=None,ls='-',hollow=False):
    return Line2D([],[],label=label,color=color,ls=ls,marker=marker,
                  lw=.8,ms=2.5,mew=.55,mfc='white' if hollow else color)


def _schemes(*schemes):
    return [Patch(facecolor=COLORS[s],edgecolor='none',label=NAMES[s]) for s in schemes]


def _legend(ax,handles,cols=1):
    # Keep the frame and its contents entirely inside the plotting rectangle.
    leg=ax.legend(handles=handles, loc='upper left', ncol=cols,
                  frameon=True, fancybox=False, framealpha=1., shadow=False,
                  edgecolor='#303030', facecolor='white', fontsize=rcParams['legend.fontsize'],
                  handlelength=1.12, handleheight=.69, handletextpad=.25, columnspacing=.45,
                  labelspacing=.08, borderpad=.22, borderaxespad=.26)
    leg.get_frame().set_linewidth(.4)
    leg.set_gid('inside-legend')
    return leg


def _holder_axis(ax):
    # Keep all observations at the numeric holder counts.
    ax.set(xlim=(1,107),xticks=(10,40,70,100),xlabel='Number of holders')
    ax.set_xticks([],minor=True)


def comparison(key, fig, ax, repo):
    """Compare the real scheme measurements at equally spaced workload categories."""
    from plot_bars import _bar, _whisker
    from plot_bar_groups import _number
    if key == 'comp_e2e':
        exp, metric, xs, schemes = 'e2e', 'LOCAL', NS, ('gp-mhac','mhac')
        xlabel, ylabel = 'Number of holders', 'Latency (ms)'
        ymax, ticks = 285, (0,100,200)
        spread, width = .39, .26
    elif key == 'comp_verify':
        exp, metric, xs, schemes = 'verify', 'verify', ATTRIBUTES, ('gp-mhac','mhac','tz23')
        xlabel, ylabel = 'Number of attributes', 'Time (ms)'
        ymax, ticks = 15.5, (0,4,8,12)
        spread, width = .37, .15
    else:
        raise KeyError(key)
    fig.subplots_adjust(left=.177,right=.992)
    rows = []
    for i, scheme in enumerate(schemes):
        row = _series(Path(repo),exp,scheme,metric,xs,NAMES[scheme])
        for j,(y,h) in enumerate(zip(row['y'],row['ci'])):
            x = j + (i-(len(schemes)-1)/2)*spread
            _bar(ax,x,y,width,COLORS[scheme],edge='black')
            _whisker(ax,x,y,h,.55)
            _number(ax,x,y,h)
        rows.append(row)
    _legend(ax,_schemes(*schemes))
    padding = .57 if key == 'comp_verify' else .52
    ax.set(xlim=(-padding,len(xs)-1+padding),ylim=(0,ymax),xticks=range(len(xs)),xticklabels=xs,
           xlabel=xlabel,ylabel=ylabel,yticks=ticks)
    return rows


def draw(key,fig,ax,repo):
    repo=Path(repo)
    rows=[]
    fig.subplots_adjust(top=.976)
    _holder_axis(ax)
    ax.tick_params(which='major',length=2,pad=1.15)
    ax.xaxis.labelpad=1.
    ax.yaxis.labelpad=1.

    if key=='comp_role':
        for scheme in ('gp-mhac','mhac'):
            for series,label,marker,ls in (
                    ('holder_checked','non-Primary','o',':'),
                    ('primary_checked','Primary','D','-.')):
                row=_series(repo,'roles',scheme,series,NS,NAMES[scheme]+' '+label)
                _line(ax,row,scheme,marker,ls,hollow=(series=='primary_checked'))
                rows.append(row)
        row=_series(repo,'roles','tz23','holder_plain',NS,'TZ23')
        _line(ax,row,'tz23','^','-')
        rows.append(row)
        _legend(ax,[*_schemes('gp-mhac','mhac'),_key('TZ23',COLORS['tz23'],'^'),
                    _key('non-Primary',marker='o',ls=':'),
                    _key('Primary',marker='D',ls='-.',hollow=True)],cols=2)
        ax.set(ylabel='Time (ms)',ylim=(0,30.7),yticks=(0,10,20,30))

    elif key=='communication_cost':
        handles=[]
        for scheme in ('gp-mhac','mhac'):
            for p,marker,ls in ((2,'o','-'),(4,'x','--')):
                row=_series(repo,'sizes',scheme,'private'+str(p),NS,f'{NAMES[scheme]}, {p} private','B')
                _line(ax,row,scheme,marker,ls,deterministic=True)
                handles.append(_key(f'{NAMES[scheme]}, {p} private',COLORS[scheme],marker,ls=ls))
                rows.append(row)
        _legend(ax,handles)
        # Leave headroom for the communication legend.
        ax.set(ylabel='Cost (KiB)',ylim=(0,48),yticks=(0,10,20,30,40))

    elif key=='network_latency':
        modes=(('LAN','LAN','D',':',True,2.85,4),
               ('WAN','WAN','^','--',False,2.5,3))
        # First column decodes scheme color; second decodes network condition.
        _legend(ax,[*_schemes('gp-mhac','mhac'),
                    *[_key(label,marker=marker,ls=ls,hollow=hollow)
                      for _,label,marker,ls,hollow,_,_ in modes]],cols=2)
        for scheme in ('gp-mhac','mhac'):
            for mode,label,marker,ls,hollow,ms,z in modes:
                row=_series(repo,'network',scheme,mode,NS,NAMES[scheme]+' '+label)
                _line(ax,row,scheme,marker,ls,hollow=hollow,zorder=z,ms=ms)
                rows.append(row)
        ax.set(ylabel='Latency (ms)',ylim=(0,425),yticks=(0,100,200,300,400))

    else:
        raise KeyError(key)
    return rows
