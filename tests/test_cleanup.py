import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from mapper.classify import classify_snapshot, ensure_classified, is_current
from mapper.common import DEFAULT_CONFIG

from tests import fake_pc


def _cfg(**over):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg.update(over)
    return cfg


class CleanupOnFakePC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.db = fake_pc.build(cls.tmp / "snapshot-test.db")
        classify_snapshot(cls.db, _cfg(), log=lambda m: None)
        cls.con = sqlite3.connect(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.con.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_planted_problem_is_found(self):
        got = {t: g for t, g in self.con.execute("SELECT title, grp FROM cleanup")}
        for title, group in fake_pc.EXPECTED.items():
            with self.subTest(title=title):
                self.assertEqual(got.get(title), group)

    def test_nothing_unexpected(self):
        got = {t for (t,) in self.con.execute("SELECT title FROM cleanup")}
        self.assertEqual(got - set(fake_pc.EXPECTED), set())

    def test_recently_used_folder_is_not_a_leftover(self):
        titles = {t for (t,) in self.con.execute("SELECT title FROM cleanup")}
        self.assertNotIn("FreshVendorThing", titles)

    def test_folder_categories(self):
        cats = dict(self.con.execute("SELECT d.path, c.cat FROM dirs d JOIN cls_dirs c ON c.id = d.id"))
        for path, want in fake_pc.EXPECTED_CATEGORIES.items():
            with self.subTest(path=path):
                self.assertEqual(cats.get(path), want)

    def test_every_suggestion_is_explained(self):
        for title, conf, reason, action in self.con.execute(
                "SELECT title, confidence, reason, action FROM cleanup"):
            with self.subTest(title=title):
                self.assertIn(conf, ("high", "medium", "low"))
                self.assertTrue(reason and action)

    def test_commands_quote_their_arguments(self):
        cmd = self.con.execute("SELECT command FROM cleanup WHERE title = 'GoneApp'").fetchone()[0]
        self.assertEqual(cmd, "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' "
                              "-Name 'GoneApp'")

    def test_overrides(self):
        db = self.tmp / "snapshot-override.db"
        shutil.copy(self.db, db)
        classify_snapshot(db, _cfg(category_overrides={"C:\\MyStuff": "media", "Steam": "utilities"}),
                          log=lambda m: None)
        con = sqlite3.connect(db)
        try:
            folder = con.execute("SELECT c.cat FROM dirs d JOIN cls_dirs c ON c.id = d.id "
                                 "WHERE d.path = 'C:\\MyStuff'").fetchone()[0]
            program = con.execute("SELECT cat FROM cls_inventory WHERE key = 'HKLM64\\steam'").fetchone()[0]
        finally:
            con.close()
        self.assertEqual((folder, program), ("media", "utilities"))

    def test_reclassifies_only_when_settings_change(self):
        cfg = _cfg()
        self.assertTrue(is_current(self.db, cfg))
        self.assertFalse(ensure_classified(self.db, cfg))
        self.assertFalse(is_current(self.db, _cfg(cleanup={"idle_days": 5})))


if __name__ == "__main__":
    unittest.main()
