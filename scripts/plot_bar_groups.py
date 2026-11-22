"""Render grouped timing comparisons with confidence intervals and values."""
def _legend(ax, keys, *, at=(.018,.985), gap=.72):
    handles, labels = zip(*keys)
    legend = ax.legend(handles, labels, loc="upper left", bbox_to_anchor=at,
                       bbox_transform=ax.transAxes, ncol=2, fancybox=False,
                       frameon=True, framealpha=1., facecolor="white", edgecolor=".16",
                       fontsize=6, handlelength=.88, handleheight=.7, handletextpad=.24,
                       columnspacing=gap, labelspacing=.10, borderpad=.18, borderaxespad=0.)
    legend.get_frame().set_linewidth(.34)
    legend.set_gid("inside-legend")
    return legend


def _number(ax, x, y, err, *, offset=.90):
    text=format(y, "#.3g").removesuffix(".")
    # Align the visible ink of the rotated Times numerals with the whisker.
    artist=ax.annotate(text,(x,y+err),xytext=(.52,offset),textcoords="offset points",
                       rotation=90,ha="center",va="bottom",fontsize=6,color="black",
                       annotation_clip=False,zorder=4,linespacing=1.)
    artist.set_gid("bar-value")
    return artist


def detection(fig,ax,repo):
    from plot_bars import _cells, _entry, _patch, _bar, _whisker, SCHEMES
    ns=(10,40,100)
    cells=_cells(repo)
    paths=(("honest","Honest",""),("withhold","Prefix","...."),("full_blame","Full blame","////"))
    series=[(s,k,label,hatch) for s in SCHEMES for k,label,hatch in paths
            if s=="gp-mhac" or k!="withhold"]
    path_keys=[(_patch("#eeeeee",hatch),label) for _,label,hatch in paths]
    scheme_keys=[(_patch(color),name) for name,color in SCHEMES.values()]
    _legend(ax,path_keys+scheme_keys,at=(.012,.985),gap=.22)
    records=[]
    for i,(scheme,path,label,hatch) in enumerate(series):
        samples=[cells["detection",scheme,path,str(n)] for n in ns]
        ys=[p.mean for p in samples]
        hs=[p.half for p in samples]
        for j,(y,h) in enumerate(zip(ys,hs)):
            x=j+(i-2)*.182
            _bar(ax,x,y,.148,SCHEMES[scheme][1],hatch)
            _whisker(ax,x,y,h,.60)
            _number(ax,x,y,h)
        records.append(_entry(f"{SCHEMES[scheme][0]} {label}",ns,ys,hs))
    ax.set(xlim=(-.53,2.53),ylim=(0,125),xlabel="Number of holders",ylabel="Time (ms)")
    ax.set_xticks(range(len(ns)),ns)
    ax.set_yticks([0,25,50,75,100])
    return records


def stage_groups(ax,repo,experiment,xs,xlabel,*,headroom):
    from plot_bars import _cells, _entry, _patch, _bar, _whisker, PHASES
    cells=_cells(repo)
    ax.figure.subplots_adjust(left=.16)
    # Matplotlib fills legend columns first; display the stages in row order.
    keys=[(_patch(PHASES[i][2]),PHASES[i][1]) for i in (0,2,1)]
    _legend(ax,keys,at=(.018,.985),gap=.44)
    records=[]
    for i,(series,label,color) in enumerate(PHASES):
        ps=[cells[experiment,"gp-mhac",series,str(x)] for x in xs]
        for j,p in enumerate(ps):
            x=j+(i-1)*.32
            _bar(ax,x,p.mean,.21,color)
            _whisker(ax,x,p.mean,p.half,.52)
            _number(ax,x,p.mean,p.half)
        records.append(_entry(label,xs,[p.mean for p in ps],[p.half for p in ps]))
    ps=[cells[experiment,"gp-mhac","compile_access",str(x)] for x in xs]
    micro=[p.mean*1000 for p in ps]
    note=ax.text(.023,.776,f"CompileAccess: {min(micro):.1f}–{max(micro):.1f} µs",
                 transform=ax.transAxes,ha="left",va="top",fontsize=6)
    note.set_gid("compile-note")
    records.append(_entry("CompileAccess",xs,[p.mean for p in ps],[p.half for p in ps],
                          kind="annotation_range",ci_plotted=False))
    ax.set(xlim=(-.65,len(xs)-1+.65),ylim=(0,headroom),xlabel=xlabel,ylabel="Time (ms)")
    ax.set_xticks(range(len(xs)),xs)
    ax.set_yticks([0,10,20,30])
    return records


def policy(fig,ax,repo):
    return stage_groups(ax,repo,"policy",(4,8,12,16,24),r"Policy size $d$",
                        headroom=35.)
