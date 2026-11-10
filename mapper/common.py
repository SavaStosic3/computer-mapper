"""Shared paths, configuration, formatting helpers and snapshot bookkeeping."""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# MAPPER_DATA_DIR / MAPPER_REPORT_DIR let test runs keep their output separate.
DATA_DIR = Path(os.environ.get("MAPPER_DATA_DIR") or ROOT / "data")
SNAPSHOT_DIR = DATA_DIR / "snapshots"
LOG_DIR = DATA_DIR / "logs"
REPORT_DIR = Path(os.environ.get("MAPPER_REPORT_DIR") or ROOT / "reports")
CONFIG_PATH = ROOT / "config.json"
# Cleanup suggestions you chose to keep (written by the browser view's "Keep" button).
KEPT_PATH = DATA_DIR / "cleanup-kept.json"

# Folder patterns whose changes are "routine churn" (caches, temp files, logs, update
# stores...). They are still scanned and recorded; reports just summarise them instead
# of listing every file. Matching is case-insensitive against the folder path,
# "*" matches any characters inside one folder name and "**" spans several folders.
DEFAULT_ROUTINE_PATTERNS = [
    "\\$Recycle.Bin\\",
    "\\System Volume Information\\",
    "\\Windows\\Temp\\",
    "\\Windows\\Prefetch\\",
    "\\Windows\\SoftwareDistribution\\",
    "\\Windows\\WinSxS\\",
    "\\Windows\\ServiceProfiles\\",
    "\\Windows\\ServiceState\\",
    "\\Windows\\System32\\config\\",
    "\\Windows\\System32\\sru\\",
    "\\Windows\\System32\\winevt\\",
    "\\Windows\\System32\\catroot2\\",
    "\\Windows\\System32\\wdi\\",
    "\\Windows\\System32\\Tasks\\",
    "\\Windows\\appcompat\\",
    "\\ProgramData\\Microsoft\\Windows Defender\\",
    "\\ProgramData\\Microsoft\\Windows\\WER\\",
    "\\ProgramData\\Microsoft\\Diagnosis\\",
    "\\ProgramData\\Microsoft\\Search\\",
    "\\ProgramData\\Microsoft\\Network\\",
    "\\ProgramData\\USOPrivate\\",
    "\\ProgramData\\USOShared\\",
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Local\\CrashDumps\\",
    "\\AppData\\Local\\ConnectedDevicesPlatform\\",
    "\\AppData\\Local\\Microsoft\\Windows\\",
    "\\AppData\\Local\\Microsoft\\Edge\\User Data\\",
    "\\AppData\\Local\\Google\\Chrome\\User Data\\",
    "\\AppData\\Local\\BraveSoftware\\",
    "\\AppData\\Local\\Mozilla\\",
    "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\",
    "\\AppData\\Local\\Packages\\*\\AC\\",
    "\\AppData\\Local\\Packages\\*\\LocalCache\\",
    "\\AppData\\Local\\Packages\\*\\TempState\\",
    "\\AppData\\Local\\Packages\\*\\Settings\\",
    "\\*Cache\\",
    "\\*Caches\\",
    "\\Cache*\\",
    "\\cache2\\",
    "\\.cache\\",
    "\\Temp\\",
    "\\tmp\\",
    "\\Logs\\",
    "\\log\\",
    "\\Crashpad\\",
    "\\Local Storage\\",
    "\\Session Storage\\",
    "\\IndexedDB\\",
    "\\WebStorage\\",
    "\\blob_storage\\",
    "\\Service Worker\\",
    "\\shared_proto_db\\",
    "\\AppData\\**\\Network\\",
    "\\AppData\\**\\sentry\\",
    "\\node_modules\\",
    "\\.git\\",
    "\\__pycache__\\",
    "\\.venv\\",
]

# Individual files with these extensions count as routine wherever they live.
DEFAULT_ROUTINE_EXTENSIONS = [
    "log", "etl", "tmp", "temp", "evtx", "dmp", "pf", "blf", "regtrans-ms",
    "db-wal", "db-shm", "db-journal", "sqlite-wal", "sqlite-shm", "log1", "log2",
    "ldb", "lock", "lck",
]

# File names ending like this are database journals and lock files: routine anywhere.
DEFAULT_ROUTINE_NAME_SUFFIXES = ["-journal", "-wal", "-shm", "~"]

# Extensions highlighted as "programs or scripts" when they appear or change.
DEFAULT_EXECUTABLE_EXTENSIONS = [
    "exe", "dll", "sys", "drv", "ocx", "cpl", "scr", "com", "msi", "msp", "msix",
    "msixbundle", "appx", "appxbundle", "ps1", "psm1", "bat", "cmd", "vbs", "vbe",
    "wsf", "hta", "jar",
]

DEFAULT_CONFIG = {
    "roots": "auto",
    "include_removable_drives": False,
    "exclude": [],
    "routine_patterns": DEFAULT_ROUTINE_PATTERNS,
    "routine_extensions": DEFAULT_ROUTINE_EXTENSIONS,
    "routine_name_suffixes": DEFAULT_ROUTINE_NAME_SUFFIXES,
    "executable_extensions": DEFAULT_EXECUTABLE_EXTENSIONS,
    "report_max_rows": 150,
    "space_change_threshold_mb": 250,
    "open_report_after_scan": True,
    # Force a category for a folder (full path) or a program (its exact name), e.g.
    # {"D:\\Projects": "development", "Wallpaper Engine": "media"}. Categories are listed in README.md.
    "category_overrides": {},
    # Thresholds for cleanup suggestions.
    "cleanup": {
        "min_cache_mb": 200,
        "min_leftover_mb": 50,
        "idle_days": 90,
        "duplicate_min_mb": 50,
        "temp_age_days": 7,
        "min_temp_mb": 50,
    },
}


def load_kept() -> dict:
    try:
        return json.loads(KEPT_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as fh:
            user = json.load(fh)
        for key, value in user.items():
            if key.startswith("_"):
                continue
            cfg[key] = value
    return cfg


def write_default_config() -> None:
    if CONFIG_PATH.exists():
        return
    doc = {"_help": "See README.md for what each setting does."}
    doc.update(DEFAULT_CONFIG)
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


# ---------------------------------------------------------------- classification


class Classifier:
    """Decides whether a path is routine churn and whether a file is executable."""

    def __init__(self, cfg: dict):
        parts = []
        for pat in cfg.get("routine_patterns", []):
            if not pat:
                continue
            # "**" spans any number of folders, "*" stays inside one folder name
            parts.append(re.escape(pat).replace(r"\*\*", "\0").replace(r"\*", r"[^\\]*").replace("\0", ".*"))
        self._rx = re.compile("|".join(parts), re.IGNORECASE) if parts else None
        self._routine_ext = {e.lower().lstrip(".") for e in cfg.get("routine_extensions", [])}
        self._routine_suffix = tuple(s.lower() for s in cfg.get("routine_name_suffixes", []) if s)
        self._exe_ext = {e.lower().lstrip(".") for e in cfg.get("executable_extensions", [])}
        self._cache: dict[str, bool] = {}

    def routine_dir(self, path: str) -> bool:
        hit = self._cache.get(path)
        if hit is None:
            probe = path if path.endswith("\\") else path + "\\"
            hit = bool(self._rx and self._rx.search(probe))
            if len(self._cache) > 500_000:
                self._cache.clear()
            self._cache[path] = hit
        return hit

    def routine_file(self, dir_path: str, ext: str, name: str = "") -> bool:
        return (ext in self._routine_ext
                or (bool(self._routine_suffix) and name.lower().endswith(self._routine_suffix))
                or self.routine_dir(dir_path))

    def executable(self, ext: str) -> bool:
        return ext in self._exe_ext


def file_ext(name: str) -> str:
    i = name.rfind(".")
    if i <= 0:
        return ""
    ext = name[i + 1:].lower()
    if len(ext) > 12 or " " in ext:
        return ""
    return ext


def area_of(path: str) -> str:
    """Group a path into a human-sized 'area' for change roll-ups."""
    comps = [c for c in path.split("\\") if c]
    if not comps:
        return path
    low = [c.lower() for c in comps]
    if len(comps) >= 2 and low[1] == "users":
        if len(comps) >= 4 and low[3] == "appdata":
            depth = 6
        else:
            depth = 4
    elif len(comps) >= 2 and low[1] in ("program files", "program files (x86)", "programdata", "windows"):
        depth = 3
    else:
        depth = 3
    out = "\\".join(comps[:depth])
    if len(comps) == 1:
        out += "\\"
    return out


# ---------------------------------------------------------------- formatting


def human_size(n: int | float | None) -> str:
    if n is None:
        return "-"
    n = float(n)
    sign = "-" if n < 0 else ""
    n = abs(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{sign}{int(n)} B"
            return f"{sign}{n:.1f} {unit}"
        n /= 1024
    return f"{sign}{n:.1f} TB"


def signed_size(n: int | None) -> str:
    if n is None:
        return "-"
    if n == 0:
        return "0 B"
    return ("+" if n > 0 else "") + human_size(n)


def fmt_time(ts: int | float | None) -> str:
    if not ts:
        return "-"
    try:
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except (OSError, OverflowError, ValueError):
        return "-"


def fmt_int(n) -> str:
    return f"{int(n or 0):,}"


# ---------------------------------------------------------------- snapshots


def snapshot_files() -> list[Path]:
    """Completed snapshot databases, oldest first."""
    if not SNAPSHOT_DIR.exists():
        return []
    return sorted(p for p in SNAPSHOT_DIR.glob("snapshot-*.db") if p.is_file())


def resolve_snapshot(name: str | None) -> Path:
    snaps = snapshot_files()
    if not snaps:
        raise SystemExit("No snapshots yet. Run a scan first.")
    if not name or name == "latest":
        return snaps[-1]
    p = Path(name)
    if p.exists():
        return p.resolve()
    for s in snaps:
        if s.name == name or s.stem == name or name in s.stem:
            return s
    raise SystemExit(f"Snapshot not found: {name}")


def connect_ro(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def read_meta(con: sqlite3.Connection, table: str = "meta") -> dict:
    try:
        return {k: v for k, v in con.execute(f"SELECT key, value FROM {table}")}
    except sqlite3.OperationalError:
        return {}


def has_table(con: sqlite3.Connection, name: str, schema: str = "main") -> bool:
    row = con.execute(
        f"SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None
