"""Walk every folder on the selected drives and record each file and folder in SQLite.

Design notes
- os.scandir on Windows returns size, timestamps and attributes straight from the
  directory listing, so no file is ever opened. OneDrive "online-only" files are not
  downloaded by the scan.
- Junctions and symbolic links to folders are recorded but not followed, which avoids
  double counting and infinite loops (e.g. "C:\\Users\\me\\Application Data").
- Folders are walked breadth-first so that folder ids, and therefore file rows, are
  written in increasing order. That keeps SQLite inserts append-only and fast.
- Folder sizes are the sum of file sizes ("size" in Explorer), not space on disk.
  Hard-linked files (common in C:\\Windows\\WinSxS) are counted in every folder that
  links them, so system folder totals can exceed what the drive actually uses.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import string
import sqlite3
import time
from collections import deque

from .common import file_ext

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
NAME_SURROGATE_BIT = 0x20000000  # set for junctions, symlinks, WSL links: "points elsewhere"

KIND_NORMAL = 0
KIND_LINK = 1        # junction / symlink: recorded, not followed
KIND_UNREADABLE = 2  # listing failed (usually access denied)
KIND_EXCLUDED = 3    # skipped by config

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3

SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE drives(root TEXT PRIMARY KEY, label TEXT, fs TEXT, total INTEGER, used INTEGER, free INTEGER);
CREATE TABLE dirs(
    id INTEGER PRIMARY KEY,
    parent INTEGER,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    depth INTEGER,
    mtime INTEGER,
    ctime INTEGER,
    attrs INTEGER,
    kind INTEGER NOT NULL DEFAULT 0,
    link_target TEXT,
    error TEXT,
    files INTEGER DEFAULT 0,
    subdirs INTEGER DEFAULT 0,
    size INTEGER DEFAULT 0,
    tree_files INTEGER DEFAULT 0,
    tree_dirs INTEGER DEFAULT 0,
    tree_size INTEGER DEFAULT 0,
    prev_tree_size INTEGER,
    prev_tree_files INTEGER
);
CREATE TABLE files(
    dir INTEGER NOT NULL,
    name TEXT NOT NULL,
    ext TEXT,
    size INTEGER,
    mtime INTEGER,
    ctime INTEGER,
    attrs INTEGER,
    PRIMARY KEY(dir, name)
) WITHOUT ROWID;
"""

POST_INDEXES = """
CREATE INDEX dirs_path ON dirs(path);
CREATE INDEX dirs_parent ON dirs(parent);
"""


def _long(path: str) -> str:
    """Prefix a path so Windows APIs accept more than 260 characters."""
    if path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def _strip_long(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def _join(parent: str, name: str) -> str:
    return parent + name if parent.endswith("\\") else parent + "\\" + name


def list_drives(include_removable: bool = False) -> list[str]:
    k32 = ctypes.windll.kernel32
    mask = k32.GetLogicalDrives()
    roots = []
    for i, letter in enumerate(string.ascii_uppercase):
        if mask & (1 << i):
            root = f"{letter}:\\"
            kind = k32.GetDriveTypeW(root)
            if kind == DRIVE_FIXED or (include_removable and kind == DRIVE_REMOVABLE):
                roots.append(root)
    return roots


def volume_info(root: str) -> tuple[str, str]:
    label = ctypes.create_unicode_buffer(261)
    fs = ctypes.create_unicode_buffer(261)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), label, 261, None, None, None, fs, 261
    )
    return (label.value, fs.value) if ok else ("", "")


def normalise_root(root: str) -> str:
    root = root.strip().replace("/", "\\")
    if len(root) == 2 and root[1] == ":":
        root += "\\"
    if len(root) > 3 and root.endswith("\\"):
        root = root.rstrip("\\")
    if len(root) >= 2 and root[1] == ":":
        root = root[0].upper() + root[1:]
    return root


def _birth(st) -> int:
    t = getattr(st, "st_birthtime", None)
    if t is None:
        t = st.st_ctime
    return int(t)


class ScanStats:
    def __init__(self):
        self.dirs = 0
        self.files = 0
        self.bytes = 0
        self.unreadable = 0
        self.links = 0
        self.entry_errors = 0
        self.started = time.time()


def scan_tree(con: sqlite3.Connection, roots: list[str], exclude: list[str], log=print) -> ScanStats:
    """Scan roots into the dirs/files tables of an empty snapshot database."""
    excluded = {normalise_root(p).lower() for p in exclude if p}

    parents: list[int] = [0]      # index = dir id
    dsize: list[int] = [0]
    dfiles: list[int] = [0]
    ddirs: list[int] = [0]

    stats = ScanStats()
    queue: deque = deque()
    dir_rows: list[tuple] = []
    file_rows: list[tuple] = []
    next_id = 1

    for root in roots:
        root = normalise_root(root)
        try:
            st = os.stat(root)
            mtime, ctime, attrs = int(st.st_mtime), _birth(st), getattr(st, "st_file_attributes", 0)
        except OSError:
            mtime = ctime = attrs = None
        name = root.rstrip("\\") if len(root) <= 3 else os.path.basename(root)
        queue.append((next_id, None, root, name, 0, mtime, ctime, attrs))
        parents.append(0); dsize.append(0); dfiles.append(0); ddirs.append(0)
        next_id += 1

    insert_dir = (
        "INSERT INTO dirs(id, parent, path, name, depth, mtime, ctime, attrs, kind, link_target, error, files, subdirs, size)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    )
    insert_file = "INSERT OR IGNORE INTO files(dir, name, ext, size, mtime, ctime, attrs) VALUES (?,?,?,?,?,?,?)"

    last_report = time.time()

    def flush():
        if dir_rows:
            con.executemany(insert_dir, dir_rows)
            dir_rows.clear()
        if file_rows:
            con.executemany(insert_file, file_rows)
            file_rows.clear()

    while queue:
        did, parent, path, name, depth, mtime, ctime, attrs = queue.popleft()
        stats.dirs += 1
        n_files = n_dirs = total = 0
        error = None
        kind = KIND_NORMAL

        if path.lower() in excluded:
            kind = KIND_EXCLUDED
            error = "excluded by config"
        else:
            try:
                with os.scandir(_long(path)) as it:
                    while True:
                        try:
                            entry = next(it)
                        except StopIteration:
                            break
                        except OSError as exc:  # listing broke part way
                            error = f"listing incomplete: {exc.strerror or exc}"
                            break
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            stats.entry_errors += 1
                            continue
                        a = st.st_file_attributes
                        ename = entry.name
                        if a & FILE_ATTRIBUTE_DIRECTORY:
                            child = _join(path, ename)
                            cid = next_id
                            next_id += 1
                            parents.append(did); dsize.append(0); dfiles.append(0); ddirs.append(0)
                            n_dirs += 1
                            if a & FILE_ATTRIBUTE_REPARSE_POINT and st.st_reparse_tag & NAME_SURROGATE_BIT:
                                target = None
                                try:
                                    target = _strip_long(os.readlink(_long(child)))
                                except OSError:
                                    pass
                                stats.dirs += 1
                                stats.links += 1
                                dir_rows.append((cid, did, child, ename, depth + 1, int(st.st_mtime), _birth(st),
                                                 a, KIND_LINK, target, None, 0, 0, 0))
                            else:
                                queue.append((cid, did, child, ename, depth + 1, int(st.st_mtime), _birth(st), a))
                        else:
                            size = st.st_size
                            n_files += 1
                            total += size
                            file_rows.append((did, ename, file_ext(ename), size, int(st.st_mtime), _birth(st), a))
            except PermissionError:
                kind = KIND_UNREADABLE
                error = "access denied"
            except FileNotFoundError:
                kind = KIND_UNREADABLE
                error = "vanished during scan"
            except OSError as exc:
                kind = KIND_UNREADABLE
                error = str(exc.strerror or exc)

        if kind == KIND_UNREADABLE:
            stats.unreadable += 1
        dsize[did] = total
        dfiles[did] = n_files
        ddirs[did] = n_dirs
        stats.files += n_files
        stats.bytes += total
        dir_rows.append((did, parent, path, name, depth, mtime, ctime, attrs, kind, None, error,
                         n_files, n_dirs, total))

        if len(file_rows) >= 50_000 or len(dir_rows) >= 20_000:
            flush()
            now = time.time()
            if now - last_report >= 10:
                last_report = now
                rate = stats.files / max(now - stats.started, 0.001)
                log(f"  {stats.dirs:>10,} folders  {stats.files:>12,} files  "
                    f"{stats.bytes / 2**30:8.1f} GB  ({rate:,.0f} files/s)  {path[:90]}")
    flush()

    # Roll direct totals up into every ancestor. Children always have larger ids
    # than their parents, so one reverse pass is enough.
    n = len(parents)
    tsize = dsize[:]
    tfiles = dfiles[:]
    tdirs = ddirs[:]
    for i in range(n - 1, 0, -1):
        p = parents[i]
        if p:
            tsize[p] += tsize[i]
            tfiles[p] += tfiles[i]
            tdirs[p] += tdirs[i]
    con.executemany(
        "UPDATE dirs SET tree_size=?, tree_files=?, tree_dirs=? WHERE id=?",
        ((tsize[i], tfiles[i], tdirs[i], i) for i in range(1, n)),
    )
    return stats


def record_drives(con: sqlite3.Connection, roots: list[str]) -> None:
    for root in roots:
        root = normalise_root(root)
        drive = root[:3] if len(root) >= 2 and root[1] == ":" else root
        label, fs = volume_info(drive)
        try:
            du = shutil.disk_usage(drive)
            total, used, free = du.total, du.used, du.free
        except OSError:
            total = used = free = None
        con.execute("INSERT OR REPLACE INTO drives VALUES (?,?,?,?,?,?)", (root, label, fs, total, used, free))


def create_snapshot_db(path) -> sqlite3.Connection:
    con = sqlite3.connect(path, isolation_level=None)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.execute("PRAGMA temp_store=MEMORY")
    con.execute("PRAGMA cache_size=-262144")  # 256 MB
    con.executescript(SCHEMA)
    return con


def finish_indexes(con: sqlite3.Connection) -> None:
    con.executescript(POST_INDEXES)
    con.execute("ANALYZE")
