"""Local, read-only web viewer for snapshots: python -m mapper browse

Serves on 127.0.0.1 only. Requests with any other Host header are refused (blocks DNS
rebinding), and the action endpoints (show a file in Explorer, open one of a fixed list of
Settings pages, mark a cleanup suggestion as "keep") need a per-run token that only the
page itself knows. The viewer never deletes or changes anything on disk.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import subprocess
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .classify import ensure_classified, fingerprint
from .cleanup import GROUPS as CLEANUP_GROUPS
from .common import (
    KEPT_PATH, REPORT_DIR, connect_ro, has_table, load_config, load_kept as _kept, read_meta, snapshot_files,
)
from .inventory import CATEGORIES
from .rules import CATEGORIES as TAGS, GROUPS as TAG_GROUPS

STATIC = Path(__file__).resolve().parent / "static"
TOKEN = secrets.token_urlsafe(24)
_types_cache: dict[str, list] = {}
_lock = threading.Lock()
_classify_lock = threading.Lock()
_classified: set[str] = set()

# Pages the viewer may open for you (nothing else can be launched).
OPENABLE = {
    "apps": "ms-settings:appsfeatures",
    "startup": "ms-settings:startupapps",
    "storage": "ms-settings:storagesense",
    "tasks": "taskschd.msc",
    "services": "services.msc",
    "recycle": "shell:RecycleBinFolder",
}


def _snap(name: str | None) -> Path:
    snaps = snapshot_files()
    if not snaps:
        raise LookupError("No snapshots yet. Run a scan first.")
    snap = None
    if not name or name == "latest":
        snap = snaps[-1]
    else:
        snap = next((s for s in snaps if s.stem == name), None)
    if snap is None:
        raise LookupError(f"Unknown snapshot {name}")
    _ensure_classified(snap)
    return snap


def _ensure_classified(snap: Path) -> None:
    """Tag snapshots made before the classifier existed (or after the rules changed), once."""
    cfg = load_config()
    key = f"{snap}:{fingerprint(cfg)}"
    if key in _classified:
        return
    with _classify_lock:
        if key in _classified:
            return
        try:
            if ensure_classified(snap, cfg, log=lambda m: print(m, flush=True)):
                print(f"Classified {snap.name}", flush=True)
        except Exception as exc:
            print(f"Could not classify {snap.name}: {exc}", flush=True)
        _classified.add(key)


def _int(q, key, default=0, lo=0, hi=10**12):
    try:
        v = int(q.get(key, [default])[0])
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))


def _str(q, key, default=""):
    return (q.get(key, [default])[0] or default).strip()


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _dict(row) -> dict:
    return {k: row[k] for k in row.keys()}


# ---------------------------------------------------------------- API handlers


def api_snapshots(q):
    out = []
    for s in reversed(snapshot_files()):
        con = connect_ro(s)
        m = read_meta(con)
        cm = read_meta(con, "chg_meta") if has_table(con, "chg_meta") else {}
        con.close()
        out.append({
            "name": s.stem, "started": m.get("started"), "files": int(m.get("total_files") or 0),
            "dirs": int(m.get("total_dirs") or 0), "size": int(m.get("total_size") or 0),
            "compared_to": cm.get("compared_to", "").replace(".db", ""), "computer": m.get("computer"),
            "db_bytes": s.stat().st_size,
        })
    return out


def api_overview(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    m = read_meta(con)
    cm = read_meta(con, "chg_meta") if has_table(con, "chg_meta") else {}
    roots = [_dict(r) for r in con.execute(
        "SELECT d.id, d.path, d.name, d.tree_size, d.tree_files, d.tree_dirs, d.prev_tree_size, "
        "v.label, v.fs, v.total, v.used, v.free FROM dirs d LEFT JOIN drives v ON v.root = d.path "
        "WHERE d.parent IS NULL ORDER BY d.path")]
    counts = {}
    if cm:
        for change, routine, n in con.execute("SELECT change, routine, count(*) FROM chg_files GROUP BY change, routine"):
            counts[f"files_{change}_{'routine' if routine else 'normal'}"] = n
        for change, routine, n in con.execute("SELECT change, routine, count(*) FROM chg_dirs GROUP BY change, routine"):
            counts[f"dirs_{change}_{'routine' if routine else 'normal'}"] = n
        for change, n in con.execute("SELECT change, count(*) FROM chg_inventory WHERE hidden=0 GROUP BY change"):
            counts[f"inv_{change}"] = n
        counts["exe_changed"] = con.execute(
            "SELECT count(*) FROM chg_files WHERE exe=1 AND routine=0 AND change IN ('added','modified')").fetchone()[0]
    meta = {k: m.get(k) for k in ("started", "finished", "computer", "user", "elevated", "total_files",
                                  "total_dirs", "total_size", "unreadable_dirs", "scan_seconds", "os", "link_dirs")}
    classified = has_table(con, "cls_dirs")
    by_cat = []
    cleanup = {}
    if classified:
        by_cat = [_dict(r) for r in con.execute(
            "SELECT c.cat, sum(d.size) AS size FROM dirs d JOIN cls_dirs c ON c.id = d.id GROUP BY c.cat "
            "ORDER BY size DESC")]
        kept = _kept()
        for grp, k, size in con.execute("SELECT grp, key, size FROM cleanup"):
            if k in kept:
                continue
            g = cleanup.setdefault(grp, {"n": 0, "size": 0})
            g["n"] += 1
            g["size"] += size or 0
    con.close()
    return {"snapshot": snap.stem, "meta": meta, "changes": cm, "counts": counts, "roots": roots,
            "tags": TAGS, "groups": TAG_GROUPS, "classified": classified, "by_cat": by_cat, "cleanup": cleanup}


def api_dir(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    did = _int(q, "id", 0)
    path = _str(q, "path")
    if path and not did:
        row = con.execute("SELECT id FROM dirs WHERE path = ?", (path,)).fetchone()
        if not row:
            row = con.execute("SELECT id FROM dirs WHERE path = ? COLLATE NOCASE", (path,)).fetchone()
        if not row:
            con.close()
            raise LookupError(f"Folder not in this snapshot: {path}")
        did = row["id"]
    d = con.execute("SELECT * FROM dirs WHERE id = ?", (did,)).fetchone()
    if not d:
        con.close()
        raise LookupError("Folder not found")
    crumbs = []
    cur = d
    while cur is not None:
        crumbs.append({"id": cur["id"], "name": cur["name"]})
        cur = con.execute("SELECT id, name, parent FROM dirs WHERE id = ?", (cur["parent"],)).fetchone() if cur["parent"] else None
    crumbs.reverse()
    has_changes = has_table(con, "chg_files")
    limit = _int(q, "limit", 300, 1, 5000)
    offset = _int(q, "offset", 0)
    children = [_dict(r) for r in con.execute(
        "SELECT id, name, kind, link_target, error, mtime, tree_size, tree_files, tree_dirs, prev_tree_size, prev_tree_files "
        "FROM dirs WHERE parent = ? ORDER BY tree_size DESC, name COLLATE NOCASE LIMIT 3000", (did,))]
    files = [_dict(r) for r in con.execute(
        "SELECT name, ext, size, mtime, ctime, attrs FROM files WHERE dir = ? "
        "ORDER BY size DESC, name COLLATE NOCASE LIMIT ? OFFSET ?", (did, limit, offset))]
    status, removed = {}, []
    if has_changes:
        for name, change, osz in con.execute("SELECT name, change, old_size FROM chg_files WHERE dir_id = ?", (did,)):
            if change == "removed":
                removed.append({"name": name, "size": osz})
            else:
                status[name] = change
        for f in files:
            f["change"] = status.get(f["name"])
        removed_dirs = [_dict(r) for r in con.execute(
            "SELECT path, tree_size, tree_files FROM chg_dirs WHERE change='removed' AND path LIKE ? ESCAPE '\\' "
            "AND path NOT LIKE ? ESCAPE '\\'",
            (_like_prefix(d["path"]), _like_prefix(d["path"]) + "\\%"))]
    else:
        removed_dirs = []
    tag = None
    if has_table(con, "cls_dirs"):
        cats = {r[0]: r[1] for r in con.execute(
            "SELECT c.id, c.cat FROM cls_dirs c JOIN dirs d ON d.id = c.id WHERE d.parent = ?", (did,))}
        for c in children:
            c["cat"] = cats.get(c["id"])
        row = con.execute("SELECT cat, why, newest FROM cls_dirs WHERE id = ?", (did,)).fetchone()
        if row:
            tag = {"cat": row["cat"], "why": row["why"], "newest": row["newest"], "from": None}
            if not row["why"]:  # inherited: say which folder decided it
                for c in reversed(crumbs[:-1]):
                    r2 = con.execute("SELECT cat, why FROM cls_dirs WHERE id = ?", (c["id"],)).fetchone()
                    if r2 and r2["why"]:
                        tag["why"], tag["from"] = r2["why"], c
                        break
    out = {"dir": _dict(d), "crumbs": crumbs, "children": children, "files": files, "tag": tag,
           "offset": offset, "limit": limit, "removed_files": removed, "removed_dirs": removed_dirs,
           "compared": has_changes}
    con.close()
    return out


def _like_prefix(path: str) -> str:
    base = path if path.endswith("\\") else path + "\\"
    return base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def api_search(q):
    snap = _snap(_str(q, "snap"))
    text = _str(q, "q")
    if len(text) < 2:
        return {"dirs": [], "files": []}
    con = connect_ro(snap)
    pat = _like(text)
    dirs = [_dict(r) for r in con.execute(
        "SELECT id, path, tree_size, tree_files FROM dirs WHERE name LIKE ? ESCAPE '\\' "
        "ORDER BY tree_size DESC LIMIT 200", (pat,))]
    files = [_dict(r) for r in con.execute(
        "SELECT f.dir, d.path AS dir_path, f.name, f.size, f.mtime FROM files f JOIN dirs d ON d.id = f.dir "
        "WHERE f.name LIKE ? ESCAPE '\\' ORDER BY f.size DESC LIMIT 500", (pat,))]
    con.close()
    return {"dirs": dirs, "files": files}


def api_changes(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    if not has_table(con, "chg_files"):
        con.close()
        return {"rows": [], "total": 0, "compared": False}
    where, params = [], []
    change = _str(q, "change", "all")
    if change in ("added", "removed", "modified"):
        where.append("change = ?")
        params.append(change)
    routine = _str(q, "routine", "0")
    if routine in ("0", "1"):
        where.append("routine = ?")
        params.append(int(routine))
    if _str(q, "exe") == "1":
        where.append("exe = 1")
    text = _str(q, "q")
    if text:
        where.append("(dir_path LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\')")
        params += [_like(text), _like(text)]
    sql_where = ("WHERE " + " AND ".join(where)) if where else ""
    sort = _str(q, "sort", "size")
    order = {"size": "max(coalesce(new_size,0), coalesce(old_size,0)) DESC",
             "path": "dir_path COLLATE NOCASE, name COLLATE NOCASE",
             "time": "coalesce(new_mtime, old_mtime) DESC"}.get(sort, "new_size DESC")
    limit = _int(q, "limit", 100, 1, 2000)
    offset = _int(q, "offset", 0)
    total = con.execute(f"SELECT count(*) FROM chg_files {sql_where}", params).fetchone()[0]
    rows = [_dict(r) for r in con.execute(
        f"SELECT change, dir_id, dir_path, name, ext, old_size, new_size, old_mtime, new_mtime, routine, exe "
        f"FROM chg_files {sql_where} ORDER BY {order} LIMIT ? OFFSET ?", params + [limit, offset])]
    con.close()
    return {"rows": rows, "total": total, "compared": True}


def api_changed_dirs(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    if not has_table(con, "chg_dirs"):
        con.close()
        return {"rows": [], "total": 0, "compared": False}
    change = _str(q, "change", "added")
    routine = _str(q, "routine", "0")
    where = ["change = ?"]
    params: list = [change]
    if routine in ("0", "1"):
        where.append("routine = ?")
        params.append(int(routine))
    text = _str(q, "q")
    if text:
        where.append("path LIKE ? ESCAPE '\\'")
        params.append(_like(text))
    w = " AND ".join(where)
    total = con.execute(f"SELECT count(*) FROM chg_dirs WHERE {w}", params).fetchone()[0]
    rows = [_dict(r) for r in con.execute(
        f"SELECT change, dir_id, path, tree_files, tree_dirs, tree_size, exe_count, routine FROM chg_dirs "
        f"WHERE {w} ORDER BY tree_size DESC LIMIT ? OFFSET ?", params + [_int(q, "limit", 100, 1, 2000), _int(q, "offset", 0)])]
    con.close()
    return {"rows": rows, "total": total, "compared": True}


def api_space(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    if not has_table(con, "chg_meta"):
        con.close()
        return {"rows": [], "compared": False}
    t = _int(q, "mb", 100, 1, 10**7) * 2**20
    rows = [_dict(r) for r in con.execute(
        "SELECT d.id, d.path, d.prev_tree_size AS old_size, d.tree_size AS new_size, "
        "d.tree_files - d.prev_tree_files AS dfiles FROM dirs d "
        "WHERE d.prev_tree_size IS NOT NULL AND abs(d.tree_size - d.prev_tree_size) >= :t "
        "AND NOT EXISTS (SELECT 1 FROM dirs c WHERE c.parent = d.id AND c.prev_tree_size IS NOT NULL "
        "AND abs(c.tree_size - c.prev_tree_size) >= :t) "
        "ORDER BY abs(d.tree_size - d.prev_tree_size) DESC LIMIT 300", {"t": t})]
    con.close()
    return {"rows": rows, "compared": True}


def api_inventory(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    if not has_table(con, "inventory"):
        con.close()
        return {"rows": [], "counts": {}}
    cat = _str(q, "cat", "program")
    hidden = _str(q, "hidden", "0") == "1"
    want_tag = _str(q, "tag")
    tagged = has_table(con, "cls_inventory")
    counts = {}
    for c, h, n in con.execute("SELECT category, hidden, count(*) FROM inventory GROUP BY category, hidden"):
        counts.setdefault(c, {"visible": 0, "hidden": 0})["hidden" if h else "visible"] += n
    rows, tag_counts = [], {}
    sql = ("SELECT i.key, i.name, i.version, i.publisher, i.location, i.hidden, i.details, "
           + ("t.cat, t.why FROM inventory i LEFT JOIN cls_inventory t ON t.category = i.category AND t.key = i.key "
              if tagged else "NULL AS cat, NULL AS why FROM inventory i ")
           + "WHERE i.category = ? " + ("" if hidden else "AND i.hidden = 0 ") + "ORDER BY i.name COLLATE NOCASE")
    for r in con.execute(sql, (cat,)):
        tag_counts[r["cat"]] = tag_counts.get(r["cat"], 0) + 1
        if want_tag and r["cat"] != want_tag:
            continue
        item = _dict(r)
        item["details"] = json.loads(item["details"] or "{}")
        rows.append(item)
    con.close()
    return {"rows": rows, "counts": counts, "categories": CATEGORIES, "tag_counts": tag_counts}


def api_categories(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    if not has_table(con, "cls_dirs"):
        con.close()
        return {"rows": [], "classified": False}
    rows = {r["cat"]: _dict(r) for r in con.execute(
        "SELECT c.cat, sum(d.size) AS size, sum(d.files) AS files, count(*) AS dirs "
        "FROM dirs d JOIN cls_dirs c ON c.id = d.id GROUP BY c.cat")}
    if has_table(con, "inventory"):
        for cat, n in con.execute(
                "SELECT t.cat, count(*) FROM cls_inventory t JOIN inventory i ON i.category = t.category "
                "AND i.key = t.key WHERE i.hidden = 0 AND i.category <> 'update' GROUP BY t.cat"):
            rows.setdefault(cat, {"cat": cat, "size": 0, "files": 0, "dirs": 0})["items"] = n
    con.close()
    out = sorted(rows.values(), key=lambda r: -(r.get("size") or 0))
    return {"rows": out, "classified": True}


def api_category(q):
    snap = _snap(_str(q, "snap"))
    cat = _str(q, "cat")
    con = connect_ro(snap)
    if not has_table(con, "cls_dirs"):
        con.close()
        return {"dirs": [], "items": []}
    dirs = [_dict(r) for r in con.execute(
        "SELECT d.id, d.path, d.tree_size, d.tree_files, c.cat_size, c.why, c.newest FROM cls_dirs c "
        "JOIN dirs d ON d.id = c.id WHERE c.cat = ? AND c.top = 1 AND c.cat_size > 0 "
        "ORDER BY c.cat_size DESC LIMIT 300", (cat,))]
    total = con.execute("SELECT count(*) FROM cls_dirs WHERE cat = ? AND top = 1 AND cat_size > 0",
                        (cat,)).fetchone()[0]
    items = [_dict(r) for r in con.execute(
        "SELECT i.category, i.key, i.name, i.version, i.publisher, i.location, i.hidden, t.why "
        "FROM cls_inventory t JOIN inventory i ON i.category = t.category AND i.key = t.key "
        "WHERE t.cat = ? AND i.category <> 'update' ORDER BY i.hidden, i.category, i.name COLLATE NOCASE",
        (cat,))] if has_table(con, "inventory") else []
    con.close()
    return {"dirs": dirs, "total_dirs": total, "items": items, "categories": CATEGORIES}


def api_cleanup(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    if not has_table(con, "cleanup"):
        con.close()
        return {"rows": [], "groups": CLEANUP_GROUPS, "classified": False}
    kept = _kept()
    rows = []
    for r in con.execute(
            "SELECT * FROM cleanup ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, "
            "coalesce(size, 0) DESC, title COLLATE NOCASE"):
        item = _dict(r)
        item["extra"] = json.loads(item["extra"]) if item["extra"] else None
        item["kept"] = r["key"] in kept
        rows.append(item)
    meta = read_meta(con, "cls_meta")
    con.close()
    return {"rows": rows, "groups": CLEANUP_GROUPS, "classified": True, "classified_at": meta.get("classified_at")}


def api_inv_changes(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    if not has_table(con, "chg_inventory"):
        con.close()
        return {"rows": [], "compared": False}
    tagged = has_table(con, "cls_inventory")
    rows = [_dict(r) for r in con.execute(
        "SELECT i.*, " + ("t.cat FROM chg_inventory i LEFT JOIN cls_inventory t ON t.category = i.category "
                          "AND t.key = i.key " if tagged else "NULL AS cat FROM chg_inventory i ")
        + "ORDER BY i.hidden, i.category, i.change, i.name COLLATE NOCASE")]
    con.close()
    return {"rows": rows, "compared": True, "categories": CATEGORIES}


def api_largest(q):
    snap = _snap(_str(q, "snap"))
    con = connect_ro(snap)
    ext = _str(q, "ext").lower().lstrip(".")
    limit = _int(q, "limit", 300, 1, 2000)
    if ext or _str(q, "ext") == "(none)":
        ext = "" if ext == "(none)" else ext
        rows = con.execute(
            "SELECT f.dir, d.path AS dir_path, f.name, f.size, f.mtime FROM files f JOIN dirs d ON d.id = f.dir "
            "WHERE f.ext = ? ORDER BY f.size DESC LIMIT ?", (ext, limit))
    else:
        rows = con.execute(
            "SELECT f.dir, d.path AS dir_path, f.name, f.size, f.mtime FROM files f JOIN dirs d ON d.id = f.dir "
            "ORDER BY f.size DESC LIMIT ?", (limit,))
    out = [_dict(r) for r in rows]
    con.close()
    return {"rows": out}


def api_types(q):
    snap = _snap(_str(q, "snap"))
    key = f"{snap}:{snap.stat().st_mtime}"
    with _lock:
        hit = _types_cache.get(key)
    if hit is None:
        con = connect_ro(snap)
        hit = [_dict(r) for r in con.execute(
            "SELECT ext, count(*) AS files, sum(size) AS size FROM files GROUP BY ext ORDER BY size DESC LIMIT 400")]
        con.close()
        with _lock:
            _types_cache[key] = hit
    return {"rows": hit}


def api_reports(q):
    if not REPORT_DIR.exists():
        return {"rows": []}
    rows = [{"name": p.name, "bytes": p.stat().st_size, "mtime": int(p.stat().st_mtime)}
            for p in sorted(REPORT_DIR.glob("computer-map-*.html"), reverse=True)]
    return {"rows": rows}


ROUTES = {
    "/api/snapshots": api_snapshots,
    "/api/overview": api_overview,
    "/api/dir": api_dir,
    "/api/search": api_search,
    "/api/changes": api_changes,
    "/api/changed_dirs": api_changed_dirs,
    "/api/space": api_space,
    "/api/inventory": api_inventory,
    "/api/inv_changes": api_inv_changes,
    "/api/categories": api_categories,
    "/api/category": api_category,
    "/api/cleanup": api_cleanup,
    "/api/largest": api_largest,
    "/api/types": api_types,
    "/api/reports": api_reports,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "ComputerMapper"
    allowed_hosts: set[str] = set()

    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _host_ok(self) -> bool:
        return (self.headers.get("Host") or "").lower() in self.allowed_hosts

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, b"Forbidden", "text/plain")
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)
        if url.path in ("/", "/index.html"):
            page = (STATIC / "viewer.html").read_text(encoding="utf-8").replace("__TOKEN__", TOKEN)
            return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8",
                              {"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                          "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"})
        if url.path.startswith("/reports/"):
            name = urllib.parse.unquote(url.path[len("/reports/"):])
            target = (REPORT_DIR / name).resolve()
            if target.parent != REPORT_DIR.resolve() or not target.is_file() or target.suffix != ".html":
                return self._send(404, b"Not found", "text/plain")
            return self._send(200, target.read_bytes(), "text/html; charset=utf-8")
        fn = ROUTES.get(url.path)
        if not fn:
            return self._send(404, b"Not found", "text/plain")
        try:
            return self._json(200, fn(q))
        except LookupError as exc:
            return self._json(404, {"error": str(exc)})
        except Exception as exc:  # report, don't crash the server
            return self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-Token") != TOKEN:
            return self._send(403, b"Forbidden", "text/plain")
        url = urllib.parse.urlsplit(self.path)
        if url.path not in ("/api/reveal", "/api/keep", "/api/open"):
            return self._send(404, b"Not found", "text/plain")
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 65536)
            body = json.loads(self.rfile.read(length) or b"{}")
            if url.path == "/api/keep":
                if not body.get("key"):
                    return self._json(400, {"error": "missing key"})
                return self._json(200, self._keep(body))
            if url.path == "/api/open":
                target = OPENABLE.get(str(body.get("what") or ""))
                if not target:
                    return self._json(404, {"error": "Unknown page."})
                os.startfile(target)
                return self._json(200, {"ok": True})
            path = str(body.get("path") or "")
            if not path or "\n" in path or not os.path.exists(path):
                return self._json(404, {"error": "That path no longer exists."})
            if os.path.isdir(path):
                subprocess.Popen(["explorer.exe", path])
            else:
                subprocess.Popen(["explorer.exe", "/select,", path])
            return self._json(200, {"ok": True})
        except Exception as exc:
            return self._json(500, {"error": str(exc)})

    @staticmethod
    def _keep(body: dict) -> dict:
        """Mark a cleanup suggestion as 'keep' (hidden from the list in future scans too), or undo it."""
        key = str(body.get("key") or "")[:2000]
        if not key:
            raise ValueError("missing key")
        with _lock:
            kept = _kept()
            if body.get("keep"):
                kept[key] = {"title": str(body.get("title") or "")[:300],
                             "kept_at": dt.datetime.now().isoformat(timespec="seconds")}
            else:
                kept.pop(key, None)
            KEPT_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = KEPT_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(kept, indent=1, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, KEPT_PATH)
        return {"ok": True, "kept": bool(body.get("keep"))}


def serve(port: int = 8765, open_browser: bool = True) -> int:
    httpd = None
    for p in range(port, port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            port = p
            break
        except OSError:
            continue
    if httpd is None:
        raise SystemExit("Could not find a free port.")
    Handler.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    url = f"http://127.0.0.1:{port}/"
    print(f"Computer Mapper viewer running at {url}  (Ctrl+C to stop)", flush=True)
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
