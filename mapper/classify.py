"""Tag every folder and every inventory item with a category, then look for cleanup suggestions.

Results are stored in the snapshot itself (tables cls_meta, cls_dirs, cls_inventory and
cleanup), so the viewer and reports can use them. Nothing on disk is touched: the
classifier only reads the snapshot.

    python -m mapper classify [snapshot]
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import rules
from .rules import CATEGORY_IDS

CLASSIFIER_VERSION = "1"

SCHEMA = """
DROP TABLE IF EXISTS cls_meta;
DROP TABLE IF EXISTS cls_dirs;
DROP TABLE IF EXISTS cls_inventory;
DROP TABLE IF EXISTS cleanup;
CREATE TABLE cls_meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE cls_dirs(
    id INTEGER PRIMARY KEY,
    cat TEXT NOT NULL,
    why TEXT,
    newest INTEGER,
    cat_size INTEGER,
    top INTEGER
);
CREATE TABLE cls_inventory(
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    cat TEXT NOT NULL,
    why TEXT,
    PRIMARY KEY(category, key)
);
CREATE TABLE cleanup(
    key TEXT PRIMARY KEY,
    grp TEXT NOT NULL,
    rule TEXT NOT NULL,
    title TEXT NOT NULL,
    target TEXT,
    target_type TEXT,
    dir_id INTEGER,
    size INTEGER,
    count INTEGER,
    confidence TEXT,
    reason TEXT,
    action TEXT,
    command TEXT,
    settings TEXT,
    cat TEXT,
    inv_category TEXT,
    inv_key TEXT,
    extra TEXT
)
"""
INDEXES = [
    "CREATE INDEX IF NOT EXISTS cls_dirs_cat ON cls_dirs(cat, top)",
    "CREATE INDEX IF NOT EXISTS cls_inventory_cat ON cls_inventory(cat)",
]

NON_HOME = {"public", "default", "default user", "all users"}


# ---------------------------------------------------------------- helpers


_HERE = Path(__file__).resolve().parent


def fingerprint(cfg: dict) -> str:
    """Changes whenever the rules, the classifier code or the relevant settings change."""
    h = hashlib.sha1()
    h.update(json.dumps({"v": CLASSIFIER_VERSION, "o": cfg.get("category_overrides") or {},
                         "c": cfg.get("cleanup") or {}}, sort_keys=True).encode())
    for name in ("rules.py", "classify.py", "cleanup.py"):
        try:
            h.update((_HERE / name).read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:16]


def rel_from_path(p: str) -> str:
    """'c:\\users\\sam\\appdata' -> '~\\appdata', 'c:\\windows' -> '\\windows' (input lower case)."""
    rest = p[2:] if len(p) >= 2 and p[1] == ":" else p
    if not rest or rest == "\\":
        return "\\"
    rest = rest.rstrip("\\")
    m = re.match(r"^\\users\\([^\\]+)(\\.*)?$", rest)
    if m and m.group(1) not in NON_HOME:
        return "~" + (m.group(2) or "")
    return rest


def child_rel(parent_rel: str, name_l: str) -> str:
    if parent_rel == "\\":
        return "\\" + name_l
    if parent_rel == "\\users" and name_l not in NON_HOME:
        return "~"
    return parent_rel + "\\" + name_l


def tokens(text: str) -> set[str]:
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text or "")
    out = set()
    for t in re.split(r"[^A-Za-z0-9]+", text):
        t = t.lower()
        if not t or t.isdigit() or t in rules.STOPWORDS:
            continue
        if len(t) >= 3 or t in rules.SHORT_TOKENS:
            out.add(t)
    return out


def ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


_ENV_PREFIX = re.compile(r"^\\systemroot\\", re.IGNORECASE)


def normalise_target(path: str) -> str:
    p = (path or "").strip().strip('"').strip()
    if p.startswith("\\??\\"):
        p = p[4:]
    p = _ENV_PREFIX.sub(lambda m: os.environ.get("SystemRoot", r"C:\Windows") + "\\", p)
    p = os.path.expandvars(p)
    return p.replace("/", "\\")


_EXE_RX = re.compile(r"^(.+?\.(?:exe|com|bat|cmd|lnk|vbs|vbe|js|jse|wsf|ps1|msc|cpl|scr|dll|hta|pif))(?=\s|,|$)",
                     re.IGNORECASE)
_SCRIPT_ARG_RX = re.compile(
    r'"([^"]+\.(?:ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|dll|exe|scr))"|'
    r"([A-Za-z]:\\[^\s,\"]+\.(?:ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|dll|exe|scr))|"
    r"(%[A-Za-z]+%\\[^\s,\"]+\.(?:ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd|dll|exe|scr))",
    re.IGNORECASE,
)


def split_command(cmd: str) -> tuple[str, str]:
    """Return (program, rest-of-command)."""
    s = (cmd or "").strip()
    if not s:
        return "", ""
    if s.startswith('"'):
        end = s.find('"', 1)
        if end < 0:
            return s.strip('"'), ""
        return s[1:end], s[end + 1:]
    m = _EXE_RX.match(s)
    if m:
        return m.group(1), s[m.end():]
    parts = s.split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def command_targets(cmd: str) -> list[str]:
    """The program a command runs, plus scripts or DLLs it hands to a host like rundll32."""
    prog, rest = split_command(cmd)
    out = [prog] if prog else []
    for m in _SCRIPT_ARG_RX.finditer(rest):
        out.append(next(g for g in m.groups() if g))
    return out


SUSPICIOUS_COMMAND_RX = [
    (re.compile(r"\b(powershell|pwsh)(\.exe)?\b.*\s-e(nc(odedcommand)?)?\s+[a-z0-9+/=]{24,}", re.I | re.S),
     "runs an encoded (hidden) PowerShell command"),
    (re.compile(r"\b(powershell|pwsh)(\.exe)?\b.*\b(iex|invoke-expression|downloadstring|downloadfile|"
                r"invoke-webrequest|iwr|net\.webclient|frombase64string|start-bitstransfer)\b", re.I | re.S),
     "makes PowerShell download or run code from text"),
    (re.compile(r"\bmshta(\.exe)?\b.*(https?:|javascript:|vbscript:)", re.I | re.S), "uses mshta to run a script"),
    (re.compile(r"\bregsvr32(\.exe)?\b.*(/i:\s*https?:|scrobj\.dll)", re.I | re.S),
     "uses regsvr32 to load a remote script"),
    (re.compile(r"\brundll32(\.exe)?\b.*javascript:", re.I | re.S), "uses rundll32 to run a script"),
    (re.compile(r"\bcertutil(\.exe)?\b.*-(urlcache|decode)", re.I | re.S), "uses certutil to download or decode files"),
    (re.compile(r"\bbitsadmin(\.exe)?\b.*/transfer", re.I | re.S), "uses bitsadmin to download files"),
]


@dataclass
class Ctx:
    con: sqlite3.Connection
    cfg: dict
    scan_ts: float
    windir: str
    # (id, parent, path, name, kind, size, tree_size, mtime, files, tree_files)
    dirs: list = field(default_factory=list)
    by_id: dict = field(default_factory=dict)         # id -> row index
    dir_index: dict = field(default_factory=dict)     # lower path -> id
    rel: dict = field(default_factory=dict)           # id -> relative position
    cat: dict = field(default_factory=dict)
    why: dict = field(default_factory=dict)
    newest: dict = field(default_factory=dict)
    direct_newest: dict = field(default_factory=dict)
    items: list = field(default_factory=list)
    item_cat: dict = field(default_factory=dict)      # (category, key) -> (cat, why, rule-match)
    excluded: list = field(default_factory=list)

    def row(self, did):
        i = self.by_id.get(did)
        return self.dirs[i] if i is not None else None

    def dir_of(self, path: str):
        """Snapshot folder id for a path (case-insensitive), or None."""
        p = path.lower().rstrip("\\")
        if len(p) == 2 and p[1] == ":":
            p += "\\"
        return self.dir_index.get(p)

    def file_exists(self, path: str):
        """True / False when the snapshot can tell, None when it can't (unreadable, not scanned)."""
        p = normalise_target(path)
        if not p:
            return None
        if "\\" not in p:
            for d in (self.windir + "\\system32", self.windir, self.windir + "\\syswow64"):
                if self.file_exists(d + "\\" + p):
                    return True
            return None
        pl = p.lower().rstrip("\\")
        if any(pl == e or pl.startswith(e + "\\") for e in self.excluded):
            return None
        if self.dir_of(pl) is not None:  # it's a folder
            return True
        d, _, name = pl.rpartition("\\")
        did = self.dir_of(d)
        if did is not None:
            row = self.row(did)
            if row[4] != 0:
                return None
            hit = self.con.execute("SELECT 1 FROM files WHERE dir = ? AND name = ? COLLATE NOCASE",
                                   (did, name)).fetchone()
            return hit is not None
        a = d
        while "\\" in a:
            a = a.rpartition("\\")[0]
            did = self.dir_of(a)
            if did is not None:
                return False if self.row(did)[4] == 0 else None
        return None


# ---------------------------------------------------------------- inventory


def _haystack(item) -> str:
    d = item["details"]
    parts = [item["name"], item["publisher"], item["location"]]
    if item["category"] == "service":
        parts.append(d.get("service_name") or "")
        parts.append(d.get("description") or "")
    elif item["category"] == "task":
        parts.append(d.get("folder") or "")
    elif item["category"] == "store_app":
        parts.append(item["key"].split("|")[0])
    return "\n".join(p for p in parts if p)


def classify_item(item, overrides: dict):
    """(category, why, match) where match is (cat, label, confidence, note) from the rules, or None."""
    name_l = (item["name"] or "").lower()
    if name_l in overrides:
        return overrides[name_l], "your setting in config.json", None
    c = item["category"]
    if c == "update":
        return "windows", "Windows update", None
    if c == "driver":
        return "drivers", "device driver", None
    if c == "store_app":
        hit = rules.match_store_app(item["name"])
        if hit:
            cat, conf, note = hit
            m = (cat, item["name"], conf, note) if cat in ("bloat", "risky") else None
            return cat, ("known Store app" if cat != "windows" else "built into Windows"), m
        if item["details"].get("framework"):
            return "runtimes", "app framework package", None
        if item["details"].get("kind") == "System":
            return "windows", "part of Windows", None
    if c == "service" and item["hidden"]:
        return "windows", "Windows service", None
    if c == "task" and item["hidden"]:
        return "windows", "Windows task", None
    m = rules.match_software(_haystack(item))
    if m:
        return m[0], f"matches {m[1]}", m
    if c == "service" and not item["location"]:
        return "windows", "Windows service", None
    pub = (item["publisher"] or "").lower()
    if "microsoft" in pub and c in ("program", "store_app"):
        return "windows", "Microsoft component", None
    return None, None, None


# ---------------------------------------------------------------- folders


def classify_dirs(ctx: Ctx, loc_map: dict, family_map: dict, overrides: dict, log) -> None:
    con = ctx.con
    git_roots = {r[0] for r in con.execute("SELECT parent FROM dirs WHERE name = '.git' AND parent IS NOT NULL")}
    npm_cache = {r[0] for r in con.execute("SELECT parent FROM dirs WHERE name = '_cacache' AND parent IS NOT NULL")}
    names = ",".join("?" * len(rules.PROJECT_MARKER_FILES))
    exts = ",".join("?" * len(rules.PROJECT_MARKER_EXTS))
    markers = {r[0] for r in con.execute(
        f"SELECT DISTINCT dir FROM files WHERE lower(name) IN ({names}) OR ext IN ({exts})",
        list(rules.PROJECT_MARKER_FILES) + list(rules.PROJECT_MARKER_EXTS))}
    name_l_of: dict[int, str] = {}
    for did, parent, path, name, kind, *_ in ctx.dirs:
        pl = path.lower()
        nl = name.lower()
        if parent is None:
            r = rel_from_path(pl)
            pcat = None
            if r == "\\":
                prel, pname = None, ""
            else:  # a scan root that isn't a whole drive, e.g. --roots D:\Projects
                up = pl.rstrip("\\").rpartition("\\")[0]
                prel = rel_from_path(up + ("\\" if up.endswith(":") else ""))
                pname = up.rpartition("\\")[2] if not up.endswith(":") else ""
        else:
            prel = ctx.rel.get(parent, "")
            r = child_rel(prel, nl)
            pcat = ctx.cat.get(parent)
            pname = name_l_of.get(parent, "")
        ctx.rel[did] = r
        name_l_of[did] = nl
        c = w = None
        under_windows = r == "\\windows" or r.startswith("\\windows\\")
        key = pl.rstrip("\\") if len(pl) > 3 else pl
        if key in overrides:
            c, w = overrides[key], "your setting in config.json"
        elif r in rules.FOLDERS:
            c, w = rules.FOLDERS[r]
        elif key in loc_map:
            c, w = loc_map[key]
        elif prel is not None:
            tail = rules.FOLDER_TAILS.get(pname + "\\" + nl)
            if tail:
                c, w = tail
            elif prel == "~\\appdata\\local\\packages" and nl in family_map:
                c, w = family_map[nl]
            elif prel in rules.VENDOR_CONTAINERS and kind != 1:
                m = rules.match_software(name)
                if m:
                    c, w = m[0], f"folder name matches {m[1]}"
        if c is None and prel is not None and not under_windows and nl not in rules.NOT_JUNK_NAMES \
                and rules.JUNK_NAME_RX.match(nl):
            c, w = "junk", "cache, temp or log folder"
        if c is None and prel in ("~", "\\") and nl in rules.DEV_ROOT_NAMES:
            c, w = "development", "code folder"
        if c is None and prel == "~" and nl.startswith("."):
            c, w = "development", "tool settings folder"
        if c is None:
            if parent is None and r == "\\":
                # files directly on a drive root are the page file, hibernation file and similar
                c, w = "windows", "drive root (page file, hibernation file)"
            else:
                inherited = pcat or "other"
                if prel == "\\" or parent is None:
                    inherited = "personal"
                    w = "folder you created"
                if did in npm_cache:
                    c, w = "junk", "npm package cache"
                elif inherited in ("personal", "other") and (did in git_roots or did in markers):
                    c, w = "development", "code project"
                elif inherited in ("personal", "other") and nl in rules.DEV_FOLDER_NAMES:
                    c, w = "development", "project files"
                else:
                    c = inherited
        ctx.cat[did] = c
        if w:
            ctx.why[did] = w


def rollups(ctx: Ctx) -> tuple[dict, dict]:
    """Newest file time per folder tree, and each folder's size counted within its own category."""
    for did, newest in ctx.con.execute("SELECT dir, max(mtime) FROM files GROUP BY dir"):
        ctx.direct_newest[did] = newest or 0
    newest = dict(ctx.direct_newest)
    cat_size = {}
    for row in ctx.dirs:
        cat_size[row[0]] = row[5] or 0
    for row in reversed(ctx.dirs):
        did, parent = row[0], row[1]
        if parent is None:
            continue
        n = newest.get(did, 0)
        if n > newest.get(parent, 0):
            newest[parent] = n
        if ctx.cat[did] == ctx.cat.get(parent):
            cat_size[parent] = cat_size.get(parent, 0) + cat_size[did]
    ctx.newest = newest
    return newest, cat_size


# ---------------------------------------------------------------- main


def classify_snapshot(db: Path, cfg: dict, log=print) -> dict:
    from . import cleanup

    t0 = time.time()
    con = sqlite3.connect(str(db))
    con.execute("PRAGMA cache_size=-262144")
    con.execute("PRAGMA temp_store=MEMORY")
    meta = {k: v for k, v in con.execute("SELECT key, value FROM meta")}
    try:
        scan_ts = dt.datetime.fromisoformat(meta.get("started", "")).timestamp()
    except ValueError:
        scan_ts = time.time()
    ctx = Ctx(con=con, cfg=cfg, scan_ts=scan_ts, windir=os.environ.get("SystemRoot", r"C:\Windows").lower())
    try:
        ctx.excluded = [e.lower().rstrip("\\") for e in json.loads(meta.get("excluded") or "[]")]
    except ValueError:
        ctx.excluded = []

    raw = cfg.get("category_overrides") or {}
    path_over, name_over = {}, {}
    for k, v in raw.items():
        if k.startswith("_") or v not in CATEGORY_IDS:
            continue
        if ":\\" in k or k.startswith("\\\\"):
            path_over[k.lower().rstrip("\\")] = v
        else:
            name_over[k.lower()] = v

    # inventory first: install folders of recognised programs then label the map
    has_inv = con.execute("SELECT 1 FROM sqlite_master WHERE name = 'inventory'").fetchone() is not None
    if has_inv:
        for category, key, name, version, publisher, location, hidden, details in con.execute(
                "SELECT category, key, name, version, publisher, location, hidden, details FROM inventory"):
            ctx.items.append({"category": category, "key": key, "name": name or "", "version": version or "",
                              "publisher": publisher or "", "location": location or "", "hidden": bool(hidden),
                              "details": json.loads(details or "{}")})
    loc_map, family_map = {}, {}
    for item in ctx.items:
        c, w, m = classify_item(item, name_over)
        ctx.item_cat[(item["category"], item["key"])] = (c, w, m)
        if not c:
            continue
        if item["category"] in ("program", "store_app") and item["location"]:
            loc = normalise_target(item["location"]).lower().rstrip("\\")
            rel = rel_from_path(loc)
            if loc and rel not in rules.VENDOR_CONTAINERS and rel not in ("\\", "~") and rel.count("\\") >= 2:
                loc_map.setdefault(loc, (c, f"install folder of {item['name']}"))
        if item["category"] == "store_app":
            family_map.setdefault(item["key"].split("|")[0].lower(), (c, f"data of {item['name']}"))

    ctx.dirs = con.execute(
        "SELECT id, parent, path, name, kind, size, tree_size, mtime, files, tree_files FROM dirs ORDER BY id").fetchall()
    for i, row in enumerate(ctx.dirs):
        ctx.by_id[row[0]] = i
        p = row[2].lower()
        ctx.dir_index[p.rstrip("\\") if len(p) > 3 else p] = row[0]
    classify_dirs(ctx, loc_map, family_map, path_over, log)
    newest, cat_size = rollups(ctx)

    # inventory items the rules didn't recognise take the category of the folder they live in
    for item in ctx.items:
        k = (item["category"], item["key"])
        c, w, m = ctx.item_cat[k]
        if c:
            continue
        for target in command_targets(item["location"]) or [item["location"]]:
            did = ctx.dir_of(normalise_target(target).rpartition("\\")[0]) if target else None
            if did is None and target:
                did = ctx.dir_of(normalise_target(target))
            if did is not None and ctx.cat.get(did) not in (None, "personal", "other"):
                c, w = ctx.cat[did], "from the folder it runs from"
                break
        ctx.item_cat[k] = (c or "software", w or "not recognised", m)

    con.executescript(SCHEMA)
    con.execute("BEGIN")
    con.executemany(
        "INSERT INTO cls_dirs(id, cat, why, newest, cat_size, top) VALUES (?,?,?,?,?,?)",
        ((row[0], ctx.cat[row[0]], ctx.why.get(row[0]), newest.get(row[0]) or None, cat_size.get(row[0], 0),
          1 if row[1] is None or ctx.cat.get(row[1]) != ctx.cat[row[0]] else 0) for row in ctx.dirs))
    con.executemany(
        "INSERT INTO cls_inventory(category, key, cat, why) VALUES (?,?,?,?)",
        ((k[0], k[1], v[0], v[1]) for k, v in ctx.item_cat.items()))
    suggestions = cleanup.find_all(ctx, log)
    con.executemany(
        "INSERT OR IGNORE INTO cleanup(key, grp, rule, title, target, target_type, dir_id, size, count, confidence, "
        "reason, action, command, settings, cat, inv_category, inv_key, extra) "
        "VALUES (:key,:grp,:rule,:title,:target,:target_type,:dir_id,:size,:count,:confidence,:reason,:action,"
        ":command,:settings,:cat,:inv_category,:inv_key,:extra)", suggestions)
    summary = {
        "version": CLASSIFIER_VERSION,
        "fingerprint": fingerprint(cfg),
        "classified_at": dt.datetime.now().isoformat(timespec="seconds"),
        "seconds": f"{time.time() - t0:.1f}",
        "suggestions": str(len(suggestions)),
    }
    con.executemany("INSERT OR REPLACE INTO cls_meta VALUES (?,?)", summary.items())
    con.execute("COMMIT")
    for sql in INDEXES:
        con.execute(sql)
    con.execute("ANALYZE cls_dirs")
    con.close()
    log(f"  classified {len(ctx.dirs):,} folders and {len(ctx.items):,} programs & system items; "
        f"{len(suggestions)} cleanup suggestions ({time.time() - t0:.1f} s)")
    return summary


def is_current(db: Path, cfg: dict) -> bool:
    try:
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        try:
            meta = {k: v for k, v in con.execute("SELECT key, value FROM cls_meta")}
        finally:
            con.close()
    except sqlite3.Error:
        return False
    return meta.get("fingerprint") == fingerprint(cfg)


def ensure_classified(db: Path, cfg: dict, log=lambda m: None) -> bool:
    """Classify a snapshot if it hasn't been yet (or the rules/settings changed). Returns True if it ran."""
    if is_current(db, cfg):
        return False
    classify_snapshot(db, cfg, log=log)
    return True
