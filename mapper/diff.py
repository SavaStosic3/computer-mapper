"""Compare a snapshot with an earlier one and store what changed inside the newer snapshot.

Results land in these tables of the newer database:
  chg_meta       which snapshot it was compared with, plus summary counts
  chg_dirs       folders that appeared or disappeared (only the topmost of each new/removed tree)
  chg_files      files added / removed / modified inside folders that exist in both scans
  chg_inventory  programs, apps, services, drivers, startup entries, tasks and updates
and dirs.prev_tree_size / prev_tree_files hold each folder's size in the earlier scan.

A file counts as modified when its size or last-modified time differs.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .common import Classifier, area_of, has_table, read_meta
from .inventory import normalised_name

CHANGE_SCHEMA = """
DROP TABLE IF EXISTS chg_meta;
DROP TABLE IF EXISTS chg_dirs;
DROP TABLE IF EXISTS chg_files;
DROP TABLE IF EXISTS chg_inventory;
CREATE TABLE chg_meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE chg_dirs(
    change TEXT NOT NULL,          -- added | removed
    dir_id INTEGER,                -- id in this snapshot (added) or NULL (removed)
    path TEXT NOT NULL,
    tree_files INTEGER, tree_dirs INTEGER, tree_size INTEGER,
    exe_count INTEGER DEFAULT 0,
    routine INTEGER DEFAULT 0,
    area TEXT
);
CREATE TABLE chg_files(
    change TEXT NOT NULL,          -- added | removed | modified
    dir_id INTEGER NOT NULL,       -- folder id in this snapshot
    dir_path TEXT NOT NULL,
    name TEXT NOT NULL,
    ext TEXT,
    old_size INTEGER, new_size INTEGER,
    old_mtime INTEGER, new_mtime INTEGER,
    routine INTEGER DEFAULT 0,
    exe INTEGER DEFAULT 0,
    area TEXT
);
CREATE TABLE chg_inventory(
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    change TEXT NOT NULL,          -- added | removed | updated | changed
    name TEXT,
    publisher TEXT,
    old_version TEXT, new_version TEXT,
    old_location TEXT, new_location TEXT,
    old_sig TEXT, new_sig TEXT,
    hidden INTEGER DEFAULT 0
);
"""

CHANGE_INDEXES = """
CREATE INDEX chg_files_kind ON chg_files(change, routine, new_size);
CREATE INDEX chg_files_dir ON chg_files(dir_id);
CREATE INDEX chg_dirs_kind ON chg_dirs(change, routine);
"""


def _script(con, sql):
    """Run several statements without executescript(), which would end the open transaction."""
    for stmt in sql.split(";"):
        if stmt.strip():
            con.execute(stmt)


def _rows(con, sql, params=()):
    cur = con.execute(sql, params)
    while True:
        chunk = cur.fetchmany(20_000)
        if not chunk:
            return
        yield from chunk


def compute_changes(new_db: Path, old_db: Path, cfg: dict, log=print) -> dict:
    t0 = time.time()
    clf = Classifier(cfg)
    exe_exts = sorted({e.lower().lstrip(".") for e in cfg.get("executable_extensions", [])})

    con = sqlite3.connect(f"file:{Path(new_db).as_posix()}", uri=True, isolation_level=None)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.execute("PRAGMA temp_store=MEMORY")
    con.execute("PRAGMA cache_size=-262144")
    con.execute("ATTACH DATABASE ? AS old", (f"file:{Path(old_db).as_posix()}?mode=ro",))
    con.execute("BEGIN")
    _script(con, "\n".join(l.split("--")[0] for l in CHANGE_SCHEMA.splitlines()))
    con.execute("UPDATE main.dirs SET prev_tree_size = NULL, prev_tree_files = NULL")

    # 1. Pair up folders that exist in both scans (same full path).
    con.execute("DROP TABLE IF EXISTS temp.dpair")
    con.execute("CREATE TEMP TABLE dpair(nid INTEGER PRIMARY KEY, oid INTEGER NOT NULL, cmp INTEGER NOT NULL)")
    con.execute(
        "INSERT OR IGNORE INTO dpair(nid, oid, cmp) "
        "SELECT n.id, o.id, (n.kind = 0 AND o.kind = 0) FROM main.dirs n JOIN old.dirs o ON o.path = n.path"
    )
    con.execute("CREATE INDEX temp.dpair_oid ON dpair(oid)")
    con.execute(
        "UPDATE main.dirs SET prev_tree_size = o.tree_size, prev_tree_files = o.tree_files "
        "FROM temp.dpair p JOIN old.dirs o ON o.id = p.oid WHERE dirs.id = p.nid"
    )
    log(f"  matched {con.execute('SELECT count(*) FROM dpair').fetchone()[0]:,} folders present in both scans")

    # 2. New and removed folder trees (topmost folder of each).
    added_parent = {}
    for did, parent in _rows(con, "SELECT id, parent FROM main.dirs WHERE id NOT IN (SELECT nid FROM dpair)"):
        added_parent[did] = parent

    def top_added(did):
        seen = 0
        while True:
            p = added_parent.get(did)
            if p is None or p not in added_parent:
                return did
            did = p
            seen += 1
            if seen > 10_000:
                return did

    exe_in_added: dict[int, int] = {}
    if exe_exts and added_parent:
        marks = ",".join("?" * len(exe_exts))
        for did, cnt in _rows(
            con,
            f"SELECT dir, count(*) FROM main.files WHERE ext IN ({marks}) "
            f"AND dir NOT IN (SELECT nid FROM dpair) GROUP BY dir",
            exe_exts,
        ):
            top = top_added(did)
            exe_in_added[top] = exe_in_added.get(top, 0) + cnt

    rows = []
    for did, path, tf, td, ts in _rows(
        con,
        "SELECT d.id, d.path, d.tree_files, d.tree_dirs, d.tree_size FROM main.dirs d "
        "WHERE d.id NOT IN (SELECT nid FROM dpair) "
        "AND (d.parent IS NULL OR d.parent IN (SELECT nid FROM dpair))",
    ):
        rows.append(("added", did, path, tf, td, ts, exe_in_added.get(did, 0),
                     1 if clf.routine_dir(path) else 0, area_of(path)))
    for path, tf, td, ts in _rows(
        con,
        "SELECT o.path, o.tree_files, o.tree_dirs, o.tree_size FROM old.dirs o "
        "WHERE o.id NOT IN (SELECT oid FROM dpair) "
        "AND (o.parent IS NULL OR o.parent IN (SELECT oid FROM dpair))",
    ):
        rows.append(("removed", None, path, tf, td, ts, 0, 1 if clf.routine_dir(path) else 0, area_of(path)))
    con.executemany("INSERT INTO chg_dirs VALUES (?,?,?,?,?,?,?,?,?)", rows)
    log(f"  folders: {sum(r[0] == 'added' for r in rows):,} new trees, {sum(r[0] == 'removed' for r in rows):,} removed trees")

    # 3. File level changes inside folders present in both scans.
    insert = "INSERT INTO chg_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
    exe_set = set(exe_exts)
    counts = {"added": 0, "removed": 0, "modified": 0}

    def emit(change, sql):
        batch = []
        for nid, path, name, ext, osz, nsz, omt, nmt in _rows(con, sql):
            ext = ext or ""
            batch.append((change, nid, path, name, ext, osz, nsz, omt, nmt,
                          1 if clf.routine_file(path, ext, name) else 0, 1 if ext in exe_set else 0, area_of(path)))
            if len(batch) >= 20_000:
                con.executemany(insert, batch)
                counts[change] += len(batch)
                batch.clear()
        if batch:
            con.executemany(insert, batch)
            counts[change] += len(batch)

    emit("added",
         "SELECT p.nid, d.path, f.name, f.ext, NULL, f.size, NULL, f.mtime "
         "FROM dpair p JOIN main.dirs d ON d.id = p.nid JOIN main.files f ON f.dir = p.nid "
         "WHERE p.cmp AND NOT EXISTS (SELECT 1 FROM old.files o WHERE o.dir = p.oid AND o.name = f.name)")
    emit("removed",
         "SELECT p.nid, d.path, o.name, o.ext, o.size, NULL, o.mtime, NULL "
         "FROM dpair p JOIN main.dirs d ON d.id = p.nid JOIN old.files o ON o.dir = p.oid "
         "WHERE p.cmp AND NOT EXISTS (SELECT 1 FROM main.files f WHERE f.dir = p.nid AND f.name = o.name)")
    emit("modified",
         "SELECT p.nid, d.path, f.name, f.ext, o.size, f.size, o.mtime, f.mtime "
         "FROM dpair p JOIN main.dirs d ON d.id = p.nid JOIN main.files f ON f.dir = p.nid "
         "JOIN old.files o ON o.dir = p.oid AND o.name = f.name "
         "WHERE p.cmp AND (o.size IS NOT f.size OR o.mtime IS NOT f.mtime)")
    log(f"  files: {counts['added']:,} added, {counts['removed']:,} removed, {counts['modified']:,} modified")

    # 4. Programs and everything else that runs.
    inv = compare_inventory(con)
    con.executemany("INSERT INTO chg_inventory VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", inv)
    log(f"  programs & system: {len(inv):,} changes")

    _script(con, CHANGE_INDEXES)

    old_meta = {k: v for k, v in con.execute("SELECT key, value FROM old.meta")}
    old_drives = [list(r) for r in con.execute("SELECT root, label, fs, total, used, free FROM old.drives")]
    summary = {
        "files": counts,
        "dirs_added": sum(r[0] == "added" for r in rows),
        "dirs_removed": sum(r[0] == "removed" for r in rows),
        "inventory": len(inv),
        "seconds": round(time.time() - t0, 1),
    }
    meta = {
        "compared_to": Path(old_db).name,
        "compared_to_started": old_meta.get("started", ""),
        "compared_to_total_size": old_meta.get("total_size", ""),
        "compared_to_total_files": old_meta.get("total_files", ""),
        "compared_to_total_dirs": old_meta.get("total_dirs", ""),
        "compared_to_os": old_meta.get("os", ""),
        "compared_to_unreadable": old_meta.get("unreadable_dirs", ""),
        "compared_to_drives": json.dumps(old_drives),
        "summary": json.dumps(summary),
    }
    con.executemany("INSERT OR REPLACE INTO chg_meta VALUES (?,?)", meta.items())
    con.execute("COMMIT")
    con.execute("DETACH DATABASE old")
    con.execute("ANALYZE")
    con.close()
    log(f"  comparison took {summary['seconds']}s")
    return summary


def compare_inventory(con: sqlite3.Connection) -> list[tuple]:
    if not has_table(con, "inventory", "main"):
        return []
    cols = "category, key, name, publisher, version, location, sig, hidden"
    new = {(r[0], r[1]): r for r in con.execute(f"SELECT {cols} FROM main.inventory")}
    old = {}
    if has_table(con, "inventory", "old"):
        old = {(r[0], r[1]): r for r in con.execute(f"SELECT {cols} FROM old.inventory")}
    out = []
    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]

    # Pair removed + added entries that are the same product under a new key
    # (common for MSI installers, which use a new product code per version).
    paired = set()
    by_name: dict[tuple, list] = {}
    for k in removed:
        if k[0] in ("program", "store_app"):
            by_name.setdefault((k[0], normalised_name(old[k][2] or "")), []).append(k)
    for k in added:
        if k[0] not in ("program", "store_app"):
            continue
        cands = by_name.get((k[0], normalised_name(new[k][2] or "")))
        if cands:
            ok = cands.pop(0)
            paired.add(ok)
            paired.add(k)
            o, n = old[ok], new[k]
            out.append((k[0], k[1], "updated", n[2], n[3], o[4], n[4], o[5], n[5], o[6], n[6], n[7]))

    for k in added:
        if k in paired:
            continue
        n = new[k]
        out.append((k[0], k[1], "added", n[2], n[3], None, n[4], None, n[5], None, n[6], n[7]))
    for k in removed:
        if k in paired:
            continue
        o = old[k]
        out.append((k[0], k[1], "removed", o[2], o[3], o[4], None, o[5], None, o[6], None, o[7]))
    for k, n in new.items():
        o = old.get(k)
        if o is None or (o[6] or "") == (n[6] or ""):
            continue
        change = "updated" if (o[4] or "") != (n[4] or "") and k[0] in ("program", "store_app") else "changed"
        out.append((k[0], k[1], change, n[2], n[3], o[4], n[4], o[5], n[5], o[6], n[6], n[7]))
    return out


def latest_previous(snapshots: list[Path], current: Path) -> Path | None:
    earlier = [s for s in snapshots if s.name < current.name]
    return earlier[-1] if earlier else None


def change_meta(con: sqlite3.Connection) -> dict:
    if not has_table(con, "chg_meta"):
        return {}
    return read_meta(con, "chg_meta")
