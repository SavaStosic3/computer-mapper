"""Command line: python -m mapper <command>

  scan      Map every file, folder and program, compare with the last scan, write a report
  classify  Re-tag folders and programs by category and refresh cleanup suggestions
  report    Rebuild the HTML report for a snapshot (default: latest)
  compare   Re-compare any two snapshots:  compare OLD NEW
  browse    Open the interactive map in your browser
  list      Show saved snapshots
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import getpass
import json
import os
import platform
import sys
import time
from pathlib import Path

from . import __version__
from .common import (
    DATA_DIR, LOG_DIR, REPORT_DIR, SNAPSHOT_DIR, connect_ro, fmt_int, human_size, load_config, read_meta,
    resolve_snapshot, snapshot_files, write_default_config,
)


class Log:
    """Print to the console and append to a log file."""

    def __init__(self, path: Path | None):
        self.fh = open(path, "a", encoding="utf-8") if path else None

    def __call__(self, msg: str = "") -> None:
        line = f"{dt.datetime.now():%H:%M:%S} {msg}"
        try:
            print(line, flush=True)
        except (UnicodeEncodeError, OSError):
            print(line.encode("ascii", "replace").decode(), flush=True)
        if self.fh:
            self.fh.write(line + "\n")
            self.fh.flush()


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def cmd_scan(args) -> int:
    from . import fsscan, inventory
    from .classify import classify_snapshot
    from .diff import compute_changes, latest_previous
    from .report import build_report

    write_default_config()
    cfg = load_config()
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for stale in SNAPSHOT_DIR.glob("*.partial"):
        try:
            stale.unlink()
        except OSError:
            pass

    stamp = dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    log = Log(LOG_DIR / f"scan-{stamp}.log")
    final = SNAPSHOT_DIR / f"snapshot-{stamp}.db"
    partial = SNAPSHOT_DIR / f"snapshot-{stamp}.db.partial"

    if args.roots:
        roots = [fsscan.normalise_root(r) for r in args.roots]
    elif cfg.get("roots", "auto") == "auto":
        roots = fsscan.list_drives(bool(cfg.get("include_removable_drives")))
    else:
        roots = [fsscan.normalise_root(r) for r in cfg["roots"]]
    # The tool's own snapshots and reports are left out so they don't show up as changes.
    exclude = list(cfg.get("exclude") or []) + [str(DATA_DIR), str(REPORT_DIR)]
    elevated = is_elevated()

    log(f"Computer Mapper {__version__}: scanning {', '.join(roots)}"
        f" ({'administrator' if elevated else 'standard user'} rights)")
    if not elevated:
        log("  Folders that need administrator rights will be recorded as unreadable.")

    t0 = time.time()
    con = fsscan.create_snapshot_db(partial)
    meta = {
        "tool_version": __version__,
        "started": dt.datetime.now().isoformat(timespec="seconds"),
        "computer": platform.node(),
        "user": getpass.getuser(),
        "elevated": "yes" if elevated else "no",
        "roots": json.dumps(roots),
        "excluded": json.dumps(exclude),
        "python": platform.python_version(),
    }
    con.execute("BEGIN")
    fsscan.record_drives(con, roots)
    stats = fsscan.scan_tree(con, roots, exclude, log=log)
    con.execute("COMMIT")
    scan_seconds = time.time() - t0
    log(f"  file scan done: {stats.dirs:,} folders, {stats.files:,} files, {human_size(stats.bytes)}"
        f" in {scan_seconds / 60:.1f} min ({stats.unreadable:,} unreadable folders)")
    log("  building indexes...")
    fsscan.finish_indexes(con)

    os_info = {}
    warnings: list[str] = []
    if not args.no_inventory:
        log("  collecting programs, apps, services, drivers, startup entries, tasks, updates...")
        items, os_info, warnings = inventory.collect(log=log)
        con.execute("BEGIN")
        inventory.store(con, items)
        con.execute("COMMIT")
        log(f"  inventory: {len(items):,} items")

    meta.update({
        "finished": dt.datetime.now().isoformat(timespec="seconds"),
        "scan_seconds": f"{scan_seconds:.0f}",
        "total_dirs": str(stats.dirs),
        "total_files": str(stats.files),
        "total_size": str(stats.bytes),
        "unreadable_dirs": str(stats.unreadable),
        "link_dirs": str(stats.links),
        "entry_errors": str(stats.entry_errors),
        "os": json.dumps(os_info),
        "inventory_warnings": json.dumps(warnings),
    })
    con.executemany("INSERT OR REPLACE INTO meta VALUES (?,?)", meta.items())
    con.close()
    os.replace(partial, final)
    log(f"  saved {final} ({human_size(final.stat().st_size)})")

    previous = latest_previous(snapshot_files(), final)
    if previous:
        log(f"Comparing with {previous.name}...")
        compute_changes(final, previous, cfg, log=log)
    else:
        log("First scan: this is the baseline. The next scan will list what changed.")

    log("Tagging folders and programs, looking for cleanup suggestions...")
    try:
        classify_snapshot(final, cfg, log=log)
    except Exception as exc:  # the map and comparison are still useful without tags
        log(f"  warning: classification failed: {type(exc).__name__}: {exc}")

    report = build_report(final, cfg, log=log)
    log(f"Report: {report}")
    log(f"Total time {(time.time() - t0) / 60:.1f} min")
    if args.open or (args.open is None and cfg.get("open_report_after_scan")):
        try:
            os.startfile(report)
        except OSError:
            pass
    return 0


def cmd_classify(args) -> int:
    from .classify import classify_snapshot
    from .report import build_report
    cfg = load_config()
    snaps = snapshot_files() if args.snapshot == "all" else [resolve_snapshot(args.snapshot)]
    log = Log(None)
    for snap in snaps:
        log(f"Classifying {snap.name}...")
        classify_snapshot(snap, cfg, log=log)
        if not args.no_report:
            log(f"  report: {build_report(snap, cfg, log=log)}")
    return 0


def cmd_report(args) -> int:
    from .classify import ensure_classified
    from .report import build_report
    cfg = load_config()
    snap = resolve_snapshot(args.snapshot)
    ensure_classified(snap, cfg, log=Log(None))
    report = build_report(snap, cfg, log=Log(None))
    print(report)
    if args.open:
        os.startfile(report)
    return 0


def cmd_compare(args) -> int:
    from .diff import compute_changes
    from .report import build_report
    cfg = load_config()
    old, new = resolve_snapshot(args.old), resolve_snapshot(args.new)
    if old.name >= new.name:
        raise SystemExit("OLD must be an earlier snapshot than NEW.")
    log = Log(None)
    log(f"Comparing {new.name} with {old.name}...")
    compute_changes(new, old, cfg, log=log)
    from .classify import ensure_classified
    ensure_classified(new, cfg, log=log)
    report = build_report(new, cfg, log=log)
    print(report)
    if args.open:
        os.startfile(report)
    return 0


def cmd_list(args) -> int:
    snaps = snapshot_files()
    if not snaps:
        print("No snapshots yet. Run: python -m mapper scan")
        return 0
    print(f"{'snapshot':<36} {'files':>12} {'folders':>10} {'size':>10} {'db size':>9}  compared to")
    for s in snaps:
        con = connect_ro(s)
        m = read_meta(con)
        cm = {}
        try:
            cm = read_meta(con, "chg_meta")
        except Exception:
            pass
        con.close()
        print(f"{s.stem:<36} {fmt_int(m.get('total_files')):>12} {fmt_int(m.get('total_dirs')):>10} "
              f"{human_size(int(m.get('total_size') or 0)):>10} {human_size(s.stat().st_size):>9}  "
              f"{cm.get('compared_to', '-')}")
    return 0


def cmd_browse(args) -> int:
    from .viewer import serve
    return serve(port=args.port, open_browser=not args.no_open)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m mapper", description="Map every file, folder and program on this PC.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan now, compare with the previous scan, write a report")
    p.add_argument("--roots", nargs="+", help="scan only these folders/drives (default: all fixed drives)")
    p.add_argument("--no-inventory", action="store_true", help="skip programs/services/tasks inventory")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--open", dest="open", action="store_true", default=None, help="open the report when done")
    g.add_argument("--no-open", dest="open", action="store_false", help="do not open the report")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("classify", help="re-tag folders/programs and refresh cleanup suggestions")
    p.add_argument("snapshot", nargs="?", default="latest", help="snapshot name, 'latest' (default) or 'all'")
    p.add_argument("--no-report", action="store_true", help="don't rebuild the HTML report afterwards")
    p.set_defaults(fn=cmd_classify)

    p = sub.add_parser("report", help="rebuild the HTML report for a snapshot")
    p.add_argument("snapshot", nargs="?", default="latest")
    p.add_argument("--open", action="store_true")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("compare", help="compare two snapshots (stores the result in NEW)")
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--open", action="store_true")
    p.set_defaults(fn=cmd_compare)

    p = sub.add_parser("browse", help="open the interactive map in your browser")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-open", action="store_true", help="start the server without opening a browser")
    p.set_defaults(fn=cmd_browse)

    p = sub.add_parser("list", help="list saved snapshots")
    p.set_defaults(fn=cmd_list)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
