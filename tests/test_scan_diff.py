"""Scan a real (temporary) folder twice and check the comparison finds every change."""

import json
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from mapper import fsscan
from mapper.common import DEFAULT_CONFIG
from mapper.diff import compute_changes


def scan(root: Path, db: Path) -> fsscan.ScanStats:
    con = fsscan.create_snapshot_db(db)
    con.execute("BEGIN")
    stats = fsscan.scan_tree(con, [fsscan.normalise_root(str(root))], [], log=lambda m: None)
    con.execute("COMMIT")
    fsscan.finish_indexes(con)
    con.executemany("INSERT OR REPLACE INTO meta VALUES (?,?)", [
        ("started", time.strftime("%Y-%m-%dT%H:%M:%S")), ("total_size", str(stats.bytes)),
        ("total_files", str(stats.files)), ("total_dirs", str(stats.dirs))])
    con.commit()
    con.close()
    return stats


def write(path: Path, size: int):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


class ScanAndCompare(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "tree"
        write(self.root / "docs" / "a.txt", 100)
        write(self.root / "docs" / "b.txt", 200)
        write(self.root / "docs" / "keep.txt", 300)
        write(self.root / "old" / "sub" / "c.bin", 1000)
        write(self.root / "old" / "d.bin", 500)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_counts_and_sizes(self):
        stats = scan(self.root, self.tmp / "s1.db")
        self.assertEqual(stats.files, 5)
        self.assertEqual(stats.bytes, 2100)
        con = sqlite3.connect(self.tmp / "s1.db")
        try:
            top = con.execute("SELECT tree_size, tree_files, tree_dirs FROM dirs WHERE parent IS NULL").fetchone()
            old = con.execute("SELECT tree_size FROM dirs WHERE name = 'old'").fetchone()
        finally:
            con.close()
        self.assertEqual(top, (2100, 5, 3))  # docs, old, old\sub
        self.assertEqual(old[0], 1500)

    def test_changes_are_found(self):
        scan(self.root, self.tmp / "s1.db")
        write(self.root / "docs" / "new.txt", 50)          # added
        (self.root / "docs" / "a.txt").unlink()             # removed
        write(self.root / "docs" / "b.txt", 999)            # modified (size changed)
        shutil.rmtree(self.root / "old")                    # removed tree
        write(self.root / "apps" / "tool" / "tool.exe", 70)  # added tree with a program
        os.utime(self.root / "docs" / "keep.txt", (1_600_000_000, 1_600_000_000))  # same size, new date -> modified
        scan(self.root, self.tmp / "s2.db")

        cfg = json.loads(json.dumps(DEFAULT_CONFIG))
        compute_changes(self.tmp / "s2.db", self.tmp / "s1.db", cfg, log=lambda m: None)
        con = sqlite3.connect(self.tmp / "s2.db")
        try:
            files = {(c, n) for c, n in con.execute("SELECT change, name FROM chg_files")}
            dirs = {(c, p.rsplit("\\", 1)[1], e) for c, p, e in con.execute("SELECT change, path, exe_count FROM chg_dirs")}
            prev = con.execute("SELECT prev_tree_size, tree_size FROM dirs WHERE parent IS NULL").fetchone()
        finally:
            con.close()
        # files in folders present in both scans are listed one by one...
        self.assertEqual(files, {("added", "new.txt"), ("removed", "a.txt"), ("modified", "b.txt"),
                                 ("modified", "keep.txt")})
        # ...while new and removed folders are listed once, at the top of each tree
        self.assertEqual(dirs, {("added", "apps", 1), ("removed", "old", 0)})
        self.assertEqual(prev, (2100, 50 + 999 + 300 + 70))  # new.txt, b.txt, keep.txt, tool.exe


if __name__ == "__main__":
    unittest.main()
