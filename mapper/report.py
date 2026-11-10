"""Self-contained HTML report for one snapshot: the current map plus what changed."""

from __future__ import annotations

import datetime as dt
import html
import json
import shutil
from pathlib import Path

from .common import (
    REPORT_DIR, connect_ro, fmt_int, fmt_time, has_table, human_size, load_kept, read_meta, signed_size,
)
from .inventory import CATEGORIES, CATEGORY_LABELS
from .rules import CATEGORIES as TAGS, GROUPS


def _group_css() -> str:
    light = ";".join(f"--g-{g}:{lc}" for g, _l, lc, _dc in GROUPS)
    dark = ";".join(f"--g-{g}:{dc}" for g, _l, _lc, dc in GROUPS)
    return (f":root{{{light}}}@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{{dark}}}}}"
            f":root[data-theme=dark]{{{dark}}}")


TAG_LABEL = {t[0]: t[1] for t in TAGS}
TAG_GROUP = {t[0]: t[2] for t in TAGS}
GROUP_LABEL = {g[0]: g[1] for g in GROUPS}


def tag(cat: str | None) -> str:
    """Category chip: a group-colored swatch next to the category's name (never color alone)."""
    if not cat:
        return ""
    return (f'<span class="tag"><i style="background:var(--g-{TAG_GROUP.get(cat, "other")})"></i>'
            f'{html.escape(TAG_LABEL.get(cat, cat))}</span>')

CSS = """
:root{--bg:#f6f6f3;--panel:#fff;--ink:#1c1c1e;--muted:#6a6a70;--line:#e3e3de;--accent:#2d6cdf;
--add:#1d8048;--rem:#c0392b;--mod:#a86a0c;--bar:#d3def4;--bar2:#f1d4cf;--chip:#efefea;--code:#f2f2ee}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#141416;--panel:#1d1d20;--ink:#ececef;
--muted:#9b9ba3;--line:#2f2f34;--accent:#7aa6ff;--add:#52c58c;--rem:#ff7b6e;--mod:#e9b14d;--bar:#2b3c5c;
--bar2:#5a2f2a;--chip:#2a2a2e;--code:#232327}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 80px}
h1{font-size:26px;margin:0 0 4px;font-weight:650;letter-spacing:-.01em}
h2{font-size:18px;margin:36px 0 10px;font-weight:650;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:22px 0 8px;font-weight:600}
p{margin:6px 0}
.sub{color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0 0}
.chip{background:var(--chip);border-radius:999px;padding:2px 10px;font-size:12.5px;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;margin-top:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:22px;font-weight:650;margin-top:2px;font-variant-numeric:tabular-nums}
.card .d{font-size:12.5px;color:var(--muted);margin-top:2px}
.pos{color:var(--add)}.neg{color:var(--rem)}
.box{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:4px 0;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:none}
th{font-size:11.5px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.p{word-break:break-all;font-family:"Cascadia Mono",Consolas,monospace;font-size:12px}
td.p .dim{color:var(--muted)}
.b{display:inline-block;font-size:11px;font-weight:650;border-radius:4px;padding:0 6px;text-transform:uppercase;letter-spacing:.03em}
.b.added{background:color-mix(in srgb,var(--add) 16%,transparent);color:var(--add)}
.b.removed{background:color-mix(in srgb,var(--rem) 16%,transparent);color:var(--rem)}
.b.modified,.b.changed,.b.updated{background:color-mix(in srgb,var(--mod) 18%,transparent);color:var(--mod)}
.b.routine{background:var(--chip);color:var(--muted)}
.bar{height:6px;border-radius:3px;background:var(--bar);min-width:2px}
.barcell{width:160px}
details{margin:10px 0}
summary{cursor:pointer;color:var(--accent);font-weight:550}
.note{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:8px;padding:10px 14px;margin:12px 0;color:var(--muted)}
.tree td.l1{padding-left:12px;font-weight:600}
.tree td.l2{padding-left:34px;color:var(--muted)}
.empty{color:var(--muted);padding:10px 12px}
code{background:var(--code);border-radius:4px;padding:1px 5px;font-family:"Cascadia Mono",Consolas,monospace;font-size:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid2>div{min-width:0}
@media (max-width:820px){.grid2{grid-template-columns:1fr}.barcell{width:80px}}
footer{margin-top:40px;color:var(--muted);font-size:12px}
.tag{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);white-space:nowrap}
.tag i{width:8px;height:8px;border-radius:2px;display:inline-block;flex:none}
.seg{display:flex;gap:2px;height:14px;margin:10px 0 6px}
.seg span{display:block;height:100%;min-width:2px}
.seg span:first-child{border-radius:4px 0 0 4px}.seg span:last-child{border-radius:0 4px 4px 0}
.b.high{background:color-mix(in srgb,var(--ink) 12%,transparent);color:var(--ink)}
.b.medium{background:var(--chip);color:var(--ink)}
.b.low{background:var(--chip);color:var(--muted)}
.why{color:var(--muted);font-size:12.5px;margin-top:2px}
"""


def e(s) -> str:
    return html.escape("" if s is None else str(s))


def _join(dir_path: str, name: str) -> str:
    return dir_path + name if dir_path.endswith("\\") else dir_path + "\\" + name


def pathcell(dir_path: str, name: str | None = None) -> str:
    if name is None:
        return f'<td class="p">{e(dir_path)}</td>'
    sep = "" if dir_path.endswith("\\") else "\\"
    return f'<td class="p"><span class="dim">{e(dir_path)}{sep}</span>{e(name)}</td>'


def badge(kind: str, label: str | None = None) -> str:
    return f'<span class="b {e(kind)}">{e(label or kind)}</span>'


def table(headers: list[str], rows: list[str], empty: str = "Nothing here.") -> str:
    if not rows:
        return f'<div class="box"><div class="empty">{e(empty)}</div></div>'
    head = "".join(
        f'<th class="n">{e(h[1:])}</th>' if h.startswith("#") else f"<th>{e(h)}</th>" for h in headers
    )
    return f'<div class="box"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def card(key: str, value: str, detail: str = "") -> str:
    return f'<div class="card"><div class="k">{e(key)}</div><div class="v">{value}</div><div class="d">{detail}</div></div>'


def delta_html(n: int | None, fmt=signed_size) -> str:
    if n is None:
        return ""
    if n == 0:
        return "no change"
    cls = "pos" if n > 0 else "neg" if n < 0 else ""
    return f'<span class="{cls}">{e(fmt(n))}</span>'


def signed_int(n: int) -> str:
    return f"{n:+,}" if n else "0"


def bar(frac: float, cls: str = "") -> str:
    pct = max(0.0, min(1.0, frac)) * 100
    style = "background:var(--bar2);" if cls == "neg" else ""
    return f'<div class="bar" style="{style}width:{pct:.1f}%"></div>'


def _when(iso: str) -> str:
    try:
        return dt.datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M")
    except (TypeError, ValueError):
        return iso or "-"


# ---------------------------------------------------------------- sections


def section_programs_changed(con, max_rows: int) -> str:
    join = ("LEFT JOIN cls_inventory c ON c.category = i.category AND c.key = i.key"
            if has_table(con, "cls_inventory") else "")
    rows = con.execute(
        f"SELECT i.category, i.change, i.name, i.publisher, i.old_version, i.new_version, i.old_location, "
        f"i.new_location, i.hidden, {'c.cat' if join else 'NULL'} AS tag "
        f"FROM chg_inventory i {join} ORDER BY i.category, i.change, i.name COLLATE NOCASE"
    ).fetchall()
    if not rows:
        return '<h2>Programs &amp; system</h2><div class="note">No programs, apps, services, drivers, startup entries, scheduled tasks or updates changed.</div>'
    out = ['<h2>Programs &amp; system</h2>']
    order = {c: i for i, (c, _) in enumerate(CATEGORIES)}
    by_cat: dict[str, list] = {}
    for r in rows:
        by_cat.setdefault(r["category"], []).append(r)
    for cat in sorted(by_cat, key=lambda c: order.get(c, 99)):
        items = by_cat[cat]
        visible = [r for r in items if not r["hidden"]]
        hidden = [r for r in items if r["hidden"]]
        counts = {}
        for r in items:
            counts[r["change"]] = counts.get(r["change"], 0) + 1
        summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        out.append(f'<h3>{e(CATEGORY_LABELS.get(cat, cat))} <span class="sub">({e(summary)})</span></h3>')

        def render(rs):
            html_rows = []
            for r in rs[:max_rows]:
                ver = ""
                if r["change"] in ("updated",) or (r["old_version"] and r["new_version"] and r["old_version"] != r["new_version"]):
                    ver = f'{e(r["old_version"] or "?")} &rarr; {e(r["new_version"] or "?")}'
                elif r["change"] == "added":
                    ver = e(r["new_version"])
                elif r["change"] == "removed":
                    ver = e(r["old_version"])
                loc = r["new_location"] if r["change"] != "removed" else r["old_location"]
                detail = e(loc or "")
                if r["change"] == "changed" and (r["old_location"] or "") != (r["new_location"] or ""):
                    detail = f'<span class="dim">was:</span> {e(r["old_location"])}<br><span class="dim">now:</span> {e(r["new_location"])}'
                elif r["change"] == "changed":
                    detail += ' <span class="dim">(setting changed: start type, account or enabled state)</span>'
                html_rows.append(
                    f'<tr><td>{badge(r["change"])}</td><td>{e(r["name"])}</td><td>{tag(r["tag"])}</td><td>{ver}</td>'
                    f'<td>{e(r["publisher"])}</td><td class="p">{detail}</td></tr>'
                )
            if len(rs) > max_rows:
                html_rows.append(f'<tr><td colspan="6" class="empty">…and {len(rs) - max_rows:,} more (see the browser view)</td></tr>')
            return table(["Change", "Name", "Category", "Version", "Publisher", "Location / command"], html_rows)

        if visible:
            out.append(render(visible))
        if hidden:
            label = {
                "program": "system components and updates",
                "store_app": "frameworks and system apps",
                "service": "Windows services",
                "driver": "drivers",
                "task": "Microsoft tasks",
            }.get(cat, "system items")
            out.append(f"<details><summary>{len(hidden):,} {e(label)}</summary>{render(hidden)}</details>")
    return "".join(out)


def section_executables(con, max_rows: int) -> str:
    rows = con.execute(
        "SELECT change, dir_path, name, new_size, old_size, new_mtime FROM chg_files "
        "WHERE exe = 1 AND routine = 0 AND change IN ('added','modified') "
        "ORDER BY change, dir_path, name LIMIT ?", (max_rows + 1,)
    ).fetchall()
    total = con.execute(
        "SELECT count(*) FROM chg_files WHERE exe = 1 AND routine = 0 AND change IN ('added','modified')"
    ).fetchone()[0]
    folders = con.execute(
        "SELECT path, tree_files, tree_size, exe_count FROM chg_dirs WHERE change='added' AND exe_count > 0 "
        "AND routine = 0 ORDER BY exe_count DESC LIMIT ?", (max_rows,)
    ).fetchall()
    out = ['<h2>New or changed programs &amp; scripts on disk</h2>',
           '<p class="sub">Executables, libraries, drivers, installers and scripts that appeared or changed '
           'outside routine areas. Updates to software you already have show up here too.</p>']
    if folders:
        out.append("<h3>New folders containing programs</h3>")
        out.append(table(["Folder", "#Programs/scripts", "#Files", "#Size"], [
            f'<tr>{pathcell(r["path"])}<td class="n">{fmt_int(r["exe_count"])}</td>'
            f'<td class="n">{fmt_int(r["tree_files"])}</td><td class="n">{human_size(r["tree_size"])}</td></tr>'
            for r in folders
        ]))
    out.append(f"<h3>Individual files in existing folders <span class=\"sub\">({total:,})</span></h3>")
    html_rows = [
        f'<tr><td>{badge(r["change"])}</td>{pathcell(r["dir_path"], r["name"])}'
        f'<td class="n">{human_size(r["new_size"])}</td><td class="n">{fmt_time(r["new_mtime"])}</td></tr>'
        for r in rows[:max_rows]
    ]
    if total > max_rows:
        html_rows.append(f'<tr><td colspan="4" class="empty">…and {total - max_rows:,} more (see the browser view)</td></tr>')
    out.append(table(["Change", "File", "#Size", "#Modified"], html_rows, "None."))
    return "".join(out)


def section_space(con, cfg, cm: dict) -> str:
    out = ['<h2>Where disk space changed</h2>']
    old_drives = {}
    try:
        old_drives = {r[0]: r for r in json.loads(cm.get("compared_to_drives") or "[]")}
    except ValueError:
        pass
    drive_rows = []
    for r in con.execute("SELECT root, label, total, used, free FROM drives ORDER BY root"):
        od = old_drives.get(r["root"])
        delta = (r["used"] - od[4]) if od and od[4] is not None and r["used"] is not None else None
        drive_rows.append(
            f'<tr><td>{e(r["root"])} <span class="sub">{e(r["label"])}</span></td>'
            f'<td class="n">{human_size(od[4]) if od else "-"}</td><td class="n">{human_size(r["used"])}</td>'
            f'<td class="n">{delta_html(delta)}</td><td class="n">{human_size(r["free"])}</td></tr>'
        )
    out.append(table(["Drive", "#Used before", "#Used now", "#Change", "#Free now"], drive_rows))

    threshold = int(cfg.get("space_change_threshold_mb", 250)) * 2**20
    rows = con.execute(
        "SELECT d.path, d.prev_tree_size AS old, d.tree_size AS new, d.tree_files - d.prev_tree_files AS dfiles "
        "FROM dirs d WHERE d.prev_tree_size IS NOT NULL AND abs(d.tree_size - d.prev_tree_size) >= :t "
        "AND NOT EXISTS (SELECT 1 FROM dirs c WHERE c.parent = d.id AND c.prev_tree_size IS NOT NULL "
        "AND abs(c.tree_size - c.prev_tree_size) >= :t) "
        "ORDER BY abs(d.tree_size - d.prev_tree_size) DESC LIMIT 40", {"t": threshold}
    ).fetchall()
    out.append(f'<h3>Folders that grew or shrank by {human_size(threshold)} or more</h3>'
               '<p class="sub">Each row is the most specific folder that accounts for the change.</p>')
    peak = max((abs(r["new"] - r["old"]) for r in rows), default=1) or 1
    out.append(table(["Folder", "#Before", "#Now", "#Change", "#Files", ""], [
        f'<tr>{pathcell(r["path"])}<td class="n">{human_size(r["old"])}</td><td class="n">{human_size(r["new"])}</td>'
        f'<td class="n">{delta_html(r["new"] - r["old"])}</td><td class="n">{signed_int(r["dfiles"] or 0)}</td>'
        f'<td class="barcell">{bar(abs(r["new"] - r["old"]) / peak, "neg" if r["new"] < r["old"] else "")}</td></tr>'
        for r in rows
    ], "No folder changed by that much."))
    return "".join(out)


def section_folders(con, max_rows: int) -> str:
    out = ['<h2>Folders that appeared or disappeared</h2>']
    for change, title in (("added", "New folders"), ("removed", "Removed folders")):
        total = con.execute("SELECT count(*), coalesce(sum(tree_size),0) FROM chg_dirs WHERE change=? AND routine=0",
                            (change,)).fetchone()
        routine = con.execute("SELECT count(*) FROM chg_dirs WHERE change=? AND routine=1", (change,)).fetchone()[0]
        rows = con.execute(
            "SELECT path, tree_files, tree_dirs, tree_size FROM chg_dirs WHERE change=? AND routine=0 "
            "ORDER BY tree_size DESC, tree_files DESC LIMIT ?", (change, max_rows)
        ).fetchall()
        out.append(f'<h3>{title} <span class="sub">({total[0]:,} folder trees, {human_size(total[1])}; '
                   f'plus {routine:,} in routine areas)</span></h3>')
        html_rows = [
            f'<tr>{pathcell(r["path"])}<td class="n">{fmt_int(r["tree_files"])}</td>'
            f'<td class="n">{fmt_int(r["tree_dirs"])}</td><td class="n">{human_size(r["tree_size"])}</td></tr>'
            for r in rows
        ]
        if total[0] > max_rows:
            html_rows.append(f'<tr><td colspan="4" class="empty">…and {total[0] - max_rows:,} more, smaller ones</td></tr>')
        out.append(table(["Folder", "#Files", "#Subfolders", "#Size"], html_rows, "None."))
    return "".join(out)


def section_areas(con) -> str:
    rows = con.execute(
        "SELECT area, routine, change, count(*) AS n, coalesce(sum(coalesce(new_size,0) - coalesce(old_size,0)),0) AS dsize "
        "FROM chg_files GROUP BY area, routine, change"
    ).fetchall()
    dir_rows = con.execute(
        "SELECT area, routine, change, sum(tree_files) AS n, "
        "sum(CASE WHEN change='added' THEN tree_size ELSE -tree_size END) AS dsize "
        "FROM chg_dirs GROUP BY area, routine, change"
    ).fetchall()
    agg: dict[tuple, dict] = {}
    for r in list(rows) + list(dir_rows):
        a = agg.setdefault((r["area"], r["routine"]), {"added": 0, "removed": 0, "modified": 0, "dsize": 0})
        a[r["change"]] += r["n"] or 0
        a["dsize"] += r["dsize"] or 0
    items = sorted(agg.items(), key=lambda kv: (kv[0][1], -(kv[1]["added"] + kv[1]["removed"] + kv[1]["modified"])))
    normal = [kv for kv in items if not kv[0][1]][:40]
    routine = [kv for kv in items if kv[0][1]][:25]

    def render(lst):
        return table(["Area", "#Added", "#Removed", "#Modified", "#Size change"], [
            f'<tr>{pathcell(k[0])}<td class="n">{fmt_int(v["added"])}</td><td class="n">{fmt_int(v["removed"])}</td>'
            f'<td class="n">{fmt_int(v["modified"])}</td><td class="n">{delta_html(v["dsize"])}</td></tr>'
            for k, v in lst
        ], "None.")

    out = ['<h2>Changes by area</h2>',
           '<p class="sub">File counts include files inside new and removed folders.</p>',
           render(normal)]
    if routine:
        out.append(f"<details><summary>Routine churn: caches, temp files, logs, browser profiles, update stores "
                   f"({len(routine)} busiest areas)</summary>{render(routine)}</details>")
    return "".join(out)


def section_file_details(con, max_rows: int) -> str:
    out = ['<h2>File changes in existing folders</h2>',
           '<p class="sub">Routine areas are left out here; the browser view can show everything.</p>']
    specs = [
        ("added", "Added files", "new_size"),
        ("modified", "Modified files", "new_size"),
        ("removed", "Removed files", "old_size"),
    ]
    for change, title, size_col in specs:
        total = con.execute("SELECT count(*) FROM chg_files WHERE change=? AND routine=0", (change,)).fetchone()[0]
        rows = con.execute(
            f"SELECT dir_path, name, old_size, new_size, old_mtime, new_mtime FROM chg_files "
            f"WHERE change=? AND routine=0 ORDER BY {size_col} DESC LIMIT ?", (change, max_rows)
        ).fetchall()
        html_rows = []
        for r in rows:
            if change == "modified":
                sizes = f'{human_size(r["old_size"])} &rarr; {human_size(r["new_size"])}'
                when = fmt_time(r["new_mtime"])
            elif change == "added":
                sizes, when = human_size(r["new_size"]), fmt_time(r["new_mtime"])
            else:
                sizes, when = human_size(r["old_size"]), fmt_time(r["old_mtime"])
            html_rows.append(f'<tr>{pathcell(r["dir_path"], r["name"])}<td class="n">{sizes}</td><td class="n">{when}</td></tr>')
        if total > max_rows:
            html_rows.append(f'<tr><td colspan="3" class="empty">…and {total - max_rows:,} more, smaller files</td></tr>')
        out.append(f'<details{" open" if change != "removed" else ""}><summary>{title} ({total:,}, largest first)</summary>'
                   f'{table(["File", "#Size", "#Modified"], html_rows, "None.")}</details>')
    return "".join(out)


def section_map(con, meta: dict) -> str:
    out = ['<h2>The map today</h2>']
    drive_rows = []
    for d in con.execute("SELECT * FROM drives ORDER BY root"):
        root = con.execute("SELECT tree_files, tree_dirs, tree_size FROM dirs WHERE parent IS NULL AND path=?",
                           (d["root"],)).fetchone()
        used_frac = (d["used"] / d["total"]) if d["total"] else 0
        drive_rows.append(
            f'<tr><td><b>{e(d["root"])}</b> <span class="sub">{e(d["label"] or "")} {e(d["fs"] or "")}</span></td>'
            f'<td class="n">{human_size(d["used"])} of {human_size(d["total"])}</td>'
            f'<td class="barcell">{bar(used_frac)}</td><td class="n">{human_size(d["free"])}</td>'
            f'<td class="n">{fmt_int(root["tree_files"]) if root else "-"}</td>'
            f'<td class="n">{fmt_int(root["tree_dirs"]) if root else "-"}</td></tr>'
        )
    out.append(table(["Drive", "#Used", "", "#Free", "#Files", "#Folders"], drive_rows))
    out.append(section_categories(con))

    out.append('<h3>Biggest folders</h3><p class="sub">Two levels deep on each drive. '
               'Run <code>Browse-Map.ps1</code> to explore every folder and file.</p>')
    rows = []
    for root in con.execute("SELECT id, path, tree_size FROM dirs WHERE parent IS NULL ORDER BY path"):
        rows.append(f'<tr><td class="p"><b>{e(root["path"])}</b></td><td class="n"><b>{human_size(root["tree_size"])}</b></td>'
                    f'<td class="n"></td><td class="barcell"></td></tr>')
        top = root["tree_size"] or 1
        for c in con.execute("SELECT id, name, tree_size, tree_files, kind FROM dirs WHERE parent=? ORDER BY tree_size DESC LIMIT 12",
                             (root["id"],)):
            if not c["tree_size"]:
                continue
            rows.append(f'<tr><td class="l1">{e(c["name"])}</td><td class="n">{human_size(c["tree_size"])}</td>'
                        f'<td class="n">{fmt_int(c["tree_files"])} files</td><td class="barcell">{bar(c["tree_size"] / top)}</td></tr>')
            for g in con.execute("SELECT name, tree_size, tree_files FROM dirs WHERE parent=? ORDER BY tree_size DESC LIMIT 5",
                                 (c["id"],)):
                if g["tree_size"] < top * 0.002:
                    continue
                rows.append(f'<tr><td class="l2">{e(g["name"])}</td><td class="n">{human_size(g["tree_size"])}</td>'
                            f'<td class="n">{fmt_int(g["tree_files"])} files</td><td class="barcell">{bar(g["tree_size"] / top)}</td></tr>')
    out.append(f'<div class="box tree"><table><tbody>{"".join(rows)}</tbody></table></div>')

    out.append('<div class="grid2"><div>')
    out.append('<h3>Space by file type</h3>')
    types = con.execute("SELECT ext, count(*) AS n, sum(size) AS s FROM files GROUP BY ext ORDER BY s DESC LIMIT 20").fetchall()
    top = types[0]["s"] if types and types[0]["s"] else 1
    out.append(table(["Type", "#Files", "#Size", ""], [
        f'<tr><td>{e("." + r["ext"] if r["ext"] else "(none)")}</td><td class="n">{fmt_int(r["n"])}</td>'
        f'<td class="n">{human_size(r["s"])}</td><td class="barcell">{bar((r["s"] or 0) / top)}</td></tr>' for r in types
    ]))
    out.append('</div><div><h3>Largest files</h3>')
    big = con.execute("SELECT d.path AS dir, f.name, f.size FROM files f JOIN dirs d ON d.id = f.dir "
                      "ORDER BY f.size DESC LIMIT 20").fetchall()
    out.append(table(["File", "#Size"], [
        f'<tr>{pathcell(r["dir"], r["name"])}<td class="n">{human_size(r["size"])}</td></tr>' for r in big
    ]))
    out.append('</div></div>')
    return "".join(out)


def section_inventory(con) -> str:
    if not has_table(con, "inventory"):
        return ""
    out = ['<h2>Everything installed and running</h2>',
           '<p class="sub">The full program inventory from this scan. Click a heading to expand it.</p>']
    specs = [
        ("program", "Installed programs", "hidden = 0", ["Name", "Category", "Version", "Publisher", "Installed", "#Size", "Location"]),
        ("store_app", "Store & MSIX apps", "hidden = 0", ["Name", "Category", "Version", "Publisher", "Location"]),
        ("startup", "Startup entries", "1=1", ["Name", "Category", "State", "Where", "Command"]),
        ("service", "Non-Windows services", "hidden = 0", ["Name", "Category", "Start", "State", "Program"]),
        ("task", "Scheduled tasks (non-Microsoft)", "hidden = 0", ["Name", "Category", "Folder", "State", "Action"]),
        ("update", "Windows updates", "1=1", ["Update", "Type", "Installed"]),
    ]
    tagged = has_table(con, "cls_inventory")
    for cat, title, where, headers in specs:
        rows = con.execute(
            f"SELECT i.name, i.version, i.publisher, i.location, i.details, {'c.cat' if tagged else 'NULL'} AS tag "
            f"FROM inventory i {'LEFT JOIN cls_inventory c ON c.category = i.category AND c.key = i.key' if tagged else ''} "
            f"WHERE i.category=? AND {where.replace('hidden', 'i.hidden')} ORDER BY i.name COLLATE NOCASE", (cat,)
        ).fetchall()
        if not tagged:
            headers = [h for h in headers if h != "Category"]
        total = con.execute("SELECT count(*) FROM inventory WHERE category=?", (cat,)).fetchone()[0]
        html_rows = []
        for r in rows:
            d = json.loads(r["details"] or "{}")
            if cat == "program":
                when = d.get("install_date") or ""
                if len(when) == 8 and when.isdigit():
                    when = f"{when[:4]}-{when[4:6]}-{when[6:]}"
                cells = [e(r["name"]), tag(r["tag"]), e(r["version"]), e(r["publisher"]), e(when),
                         human_size(d.get("size_bytes")) if d.get("size_bytes") else "", e(r["location"])]
            elif cat == "store_app":
                cells = [e(r["name"]), tag(r["tag"]), e(r["version"]), e(_publisher_cn(r["publisher"])), e(r["location"])]
            elif cat == "startup":
                cells = [e(r["name"]), tag(r["tag"]), "on" if d.get("enabled", True) else '<span class="sub">disabled</span>',
                         e(d.get("where")), e(r["location"])]
            elif cat == "service":
                cells = [e(r["name"]), tag(r["tag"]), e(d.get("start")), e(d.get("state")), e(r["location"])]
            elif cat == "task":
                cells = [e(r["name"]), tag(r["tag"]), e(d.get("folder")), e(d.get("state")), e(r["location"])]
            else:
                cells = [e(r["name"]), e(d.get("description")), e(d.get("installed"))]
            if not tagged and cat != "update":
                cells.pop(1)
            tds = []
            for h, c in zip(headers, cells):
                cls = ' class="n"' if h.startswith("#") else ' class="p"' if h in ("Location", "Command", "Program", "Action") else ""
                tds.append(f"<td{cls}>{c}</td>")
            html_rows.append("<tr>" + "".join(tds) + "</tr>")
        extra = f", {total - len(rows):,} system items hidden" if total > len(rows) else ""
        out.append(f"<details><summary>{e(title)} ({len(rows):,}{extra})</summary>{table(headers, html_rows)}</details>")
    return "".join(out)


def section_categories(con) -> str:
    """Space by category: one segmented bar by group, then the table that doubles as its legend."""
    if not has_table(con, "cls_dirs"):
        return ""
    rows = con.execute(
        "SELECT c.cat, sum(d.size) AS size, sum(d.files) AS files FROM dirs d JOIN cls_dirs c ON c.id = d.id "
        "GROUP BY c.cat ORDER BY size DESC").fetchall()
    total = sum(r["size"] or 0 for r in rows) or 1
    inv = {}
    if has_table(con, "cls_inventory") and has_table(con, "inventory"):
        inv = {r[0]: r[1] for r in con.execute(
            "SELECT c.cat, count(*) FROM cls_inventory c JOIN inventory i ON i.category = c.category AND i.key = c.key "
            "WHERE i.hidden = 0 AND i.category IN ('program','store_app') GROUP BY c.cat")}
    by_group: dict[str, int] = {}
    for r in rows:
        g = TAG_GROUP.get(r["cat"], "other")
        by_group[g] = by_group.get(g, 0) + (r["size"] or 0)
    segs = "".join(
        f'<span title="{e(GROUP_LABEL[g])}: {human_size(by_group[g])}" '
        f'style="flex:{by_group[g] / total:.5f};background:var(--g-{g})"></span>'
        for g, *_ in GROUPS if by_group.get(g))
    legend = " ".join(
        f'<span class="tag"><i style="background:var(--g-{g})"></i>{e(GROUP_LABEL[g])} {human_size(by_group[g])}</span>'
        for g, *_ in GROUPS if by_group.get(g))
    top = rows[0]["size"] if rows and rows[0]["size"] else 1
    body = [
        f'<tr><td>{tag(r["cat"])}</td><td class="n">{human_size(r["size"])}</td>'
        f'<td class="n">{(r["size"] or 0) / total * 100:.1f}%</td><td class="barcell">{bar((r["size"] or 0) / top)}</td>'
        f'<td class="n">{fmt_int(r["files"])}</td><td class="n">{fmt_int(inv.get(r["cat"], 0)) if inv.get(r["cat"]) else ""}</td></tr>'
        for r in rows if r["size"]]
    return ('<h3>Space by category</h3><p class="sub">Every folder is tagged with what it holds. '
            'Open the browser view to see which folders and programs are in each category.</p>'
            f'<div class="seg">{segs}</div><div>{legend}</div>'
            + table(["Category", "#Size", "#Share", "", "#Files", "#Programs"], body))


def section_cleanup(con, max_rows: int) -> str:
    if not has_table(con, "cleanup"):
        return ""
    from .cleanup import GROUPS as CLEAN_GROUPS
    kept = load_kept()
    all_rows = con.execute(
        "SELECT * FROM cleanup ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, "
        "coalesce(size, 0) DESC").fetchall()
    rows = [r for r in all_rows if r["key"] not in kept]
    out = ['<h2>Cleanup suggestions</h2>',
           '<p class="sub">Things that look unnecessary, like bloat, or potentially harmful, judged from names, '
           'locations and sizes. Nothing has been deleted. Check each item before removing it; the browser view has '
           '<i>Explorer</i> buttons and copyable commands. For anything that looks harmful, run a Microsoft Defender '
           'scan.'
           + (f' {len(all_rows) - len(rows):,} suggestions you marked "keep" are not shown.' if len(all_rows) > len(rows) else "")
           + '</p>']
    cards = []
    for gid, label, _desc in CLEAN_GROUPS:
        g = [r for r in rows if r["grp"] == gid]
        size = sum(r["size"] or 0 for r in g)
        cards.append(card(label, fmt_int(len(g)), human_size(size) + " could be freed" if size else ""))
    out.append(f'<div class="cards">{"".join(cards)}</div>')
    for gid, label, desc in CLEAN_GROUPS:
        g = [r for r in rows if r["grp"] == gid]
        out.append(f'<h3>{e(label)} <span class="sub">({len(g):,})</span></h3>')
        if not g:
            out.append(f'<div class="box"><div class="empty">Nothing found. Checked for: {e(desc[0].lower() + desc[1:])}</div></div>')
            continue
        html_rows = []
        for r in g[:max_rows]:
            target = r["target"] if r["target_type"] in ("folder", "file") or r["inv_category"] in (
                "startup", "task", "service") else ""
            html_rows.append(
                f'<tr><td>{badge(r["confidence"])}</td><td><b>{e(r["title"])}</b><div class="why">{e(r["reason"])}</div>'
                f'<div class="why">{e(r["action"])}{" <code>" + e(r["command"]) + "</code>" if r["command"] else ""}</div></td>'
                f'<td class="p">{e(target)}</td><td class="n">{human_size(r["size"]) if r["size"] else ""}</td></tr>')
        out.append(table(["Confidence", "Suggestion", "Where", "#Size"], html_rows))
    return "".join(out)


def _publisher_cn(pub: str) -> str:
    for part in (pub or "").split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip('"')
    return pub or ""


def section_notes(con, meta: dict) -> str:
    unreadable = con.execute("SELECT path, error FROM dirs WHERE kind = 2 ORDER BY path").fetchall()
    links = int(meta.get("link_dirs") or 0)
    excluded = json.loads(meta.get("excluded") or "[]")
    warnings = json.loads(meta.get("inventory_warnings") or "[]")
    out = ['<h2>About this scan</h2><div class="note">',
           f'<p>Folder sizes add up file sizes (like Explorer\'s "Size"), not space used on disk. Online-only OneDrive '
           f'files count at full size, and files hard-linked into several folders (common in <code>C:\\Windows</code>) '
           f'count in each one. {links:,} junctions and folder links were recorded but not followed.</p>',
           f'<p>{len(unreadable):,} folders could not be read'
           + (" because they need administrator rights. Running the scan as administrator includes most of them."
              if meta.get("elevated") != "yes" else ".") + "</p>"]
    if excluded:
        out.append(f'<p>Skipped by configuration: {", ".join(f"<code>{e(x)}</code>" for x in excluded)}</p>')
    for w in warnings:
        out.append(f"<p>Warning: {e(w)}</p>")
    out.append("</div>")
    if unreadable:
        out.append(f"<details><summary>Unreadable folders ({len(unreadable):,})</summary>" + table(
            ["Folder", "Reason"], [f'<tr>{pathcell(r["path"])}<td>{e(r["error"])}</td></tr>' for r in unreadable[:2000]]
        ) + "</details>")
    return "".join(out)


# ---------------------------------------------------------------- page


def build_report(snapshot: Path, cfg: dict, log=print) -> Path:
    con = connect_ro(snapshot)
    meta = read_meta(con)
    cm = read_meta(con, "chg_meta") if has_table(con, "chg_meta") else {}
    max_rows = int(cfg.get("report_max_rows", 150))
    os_info = json.loads(meta.get("os") or "{}")
    total_size = int(meta.get("total_size") or 0)
    total_files = int(meta.get("total_files") or 0)
    total_dirs = int(meta.get("total_dirs") or 0)

    inv_counts = {}
    if has_table(con, "inventory"):
        inv_counts = {r[0]: r[1] for r in con.execute(
            "SELECT category, count(*) FROM inventory WHERE hidden = 0 GROUP BY category")}

    title = f"Computer map: {meta.get('computer', '')}"
    when = _when(meta.get("started", ""))
    parts = [f"<h1>{e(title)}</h1>"]
    if cm:
        parts.append(f'<p class="sub">Scan of {e(when)}, compared with the scan of {e(_when(cm.get("compared_to_started", "")))}</p>')
    else:
        parts.append(f'<p class="sub">Baseline scan of {e(when)}. The next scan will show everything that changed since today.</p>')
    os_text = f'{os_info.get("caption", "Windows")} {os_info.get("display", "")} (build {os_info.get("build", "?")}.{os_info.get("ubr", "")})'
    roots = ", ".join(json.loads(meta.get("roots") or "[]"))
    mins = int(meta.get("scan_seconds") or 0) / 60
    parts.append('<div class="chips">' + "".join(f'<span class="chip">{e(c)}</span>' for c in [
        os_text, f"Drives: {roots}", f"Ran as {'administrator' if meta.get('elevated') == 'yes' else 'standard user'}",
        f"Scan took {mins:.1f} min", snapshot.name,
    ]) + "</div>")

    # Summary cards
    cards = []
    if cm:
        old_size = int(cm.get("compared_to_total_size") or 0)
        old_files = int(cm.get("compared_to_total_files") or 0)
        old_dirs = int(cm.get("compared_to_total_dirs") or 0)
        f = {r[0]: r[1] for r in con.execute("SELECT change, count(*) FROM chg_files WHERE routine = 0 GROUP BY change")}
        fr = con.execute("SELECT count(*) FROM chg_files WHERE routine = 1").fetchone()[0]
        d = {r[0]: (r[1], r[2]) for r in con.execute(
            "SELECT change, count(*), coalesce(sum(tree_files),0) FROM chg_dirs WHERE routine = 0 GROUP BY change")}
        inv = {r[0]: r[1] for r in con.execute(
            "SELECT change, count(*) FROM chg_inventory WHERE hidden = 0 AND category IN ('program','store_app') GROUP BY change")}
        cards += [
            card("Files", fmt_int(total_files), delta_html(total_files - old_files, signed_int) + " since last scan"),
            card("Folders", fmt_int(total_dirs), delta_html(total_dirs - old_dirs, signed_int) + " since last scan"),
            card("Total size", human_size(total_size), delta_html(total_size - old_size) + " since last scan"),
            card("Programs", f'<span class="pos">+{inv.get("added", 0)}</span> / <span class="neg">-{inv.get("removed", 0)}</span>',
                 f'{inv.get("updated", 0)} updated, {inv_counts.get("program", 0) + inv_counts.get("store_app", 0)} installed'),
            card("Files changed", fmt_int(sum(f.values())),
                 f'{fmt_int(f.get("added"))} added, {fmt_int(f.get("modified"))} modified, {fmt_int(f.get("removed"))} removed'
                 f'; plus {fmt_int(fr)} routine'),
            card("Folder trees", f'<span class="pos">+{d.get("added", (0, 0))[0]:,}</span> / <span class="neg">-{d.get("removed", (0, 0))[0]:,}</span>',
                 f'holding {fmt_int(d.get("added", (0, 0))[1])} new and {fmt_int(d.get("removed", (0, 0))[1])} removed files'),
        ]
    else:
        cards += [
            card("Files", fmt_int(total_files)),
            card("Folders", fmt_int(total_dirs)),
            card("Total size", human_size(total_size)),
            card("Installed programs", fmt_int(inv_counts.get("program", 0)), f'plus {fmt_int(inv_counts.get("store_app", 0))} Store apps'),
            card("Startup entries", fmt_int(inv_counts.get("startup", 0)),
                 f'{fmt_int(inv_counts.get("service", 0))} non-Windows services'),
            card("Unreadable folders", fmt_int(meta.get("unreadable_dirs")), "need administrator rights"),
        ]
    if has_table(con, "cleanup"):
        kept = load_kept()
        live = [r for r in con.execute("SELECT key, grp, size FROM cleanup") if r["key"] not in kept]
        n, freed = len(live), sum(r["size"] or 0 for r in live)
        harmful = sum(1 for r in live if r["grp"] == "harmful")
        cards.append(card("Cleanup suggestions", fmt_int(n),
                          f"{human_size(freed)} could be freed" + (f"; {harmful} potentially harmful" if harmful else "")))
    parts.append(f'<div class="cards">{"".join(cards)}</div>')

    if cm:
        old_os = json.loads(cm.get("compared_to_os") or "{}")
        if old_os and (old_os.get("build"), old_os.get("ubr")) != (os_info.get("build"), os_info.get("ubr")):
            parts.append(f'<div class="note">Windows was updated: build {e(old_os.get("build"))}.{e(old_os.get("ubr"))} '
                         f'&rarr; {e(os_info.get("build"))}.{e(os_info.get("ubr"))}</div>')
        parts.append(section_programs_changed(con, max_rows))
        parts.append(section_executables(con, max_rows))
        parts.append(section_space(con, cfg, cm))
        parts.append(section_folders(con, max_rows))
        parts.append(section_areas(con))
        parts.append(section_file_details(con, max_rows))
    parts.append(section_cleanup(con, max_rows))
    parts.append(section_map(con, meta))
    parts.append(section_inventory(con))
    parts.append(section_notes(con, meta))
    parts.append(f'<footer>Generated {dt.datetime.now():%d %b %Y %H:%M} by Computer Mapper from {e(snapshot)}</footer>')
    con.close()

    page = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{e(title)} · {e(when)}</title><style>{_group_css()}{CSS}</style></head>'
            f'<body><main>{"".join(parts)}</main></body></html>')

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = snapshot.stem.replace("snapshot-", "")
    out = REPORT_DIR / f"computer-map-{stamp}.html"
    out.write_text(page, encoding="utf-8")
    latest = REPORT_DIR / "latest.html"
    try:
        newest = sorted(REPORT_DIR.glob("computer-map-*.html"))[-1]
        if newest == out:
            shutil.copyfile(out, latest)
    except (IndexError, OSError):
        pass
    return out
