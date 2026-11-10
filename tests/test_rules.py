import unittest

from mapper import rules
from mapper.classify import command_targets, rel_from_path, split_command, tokens


class SoftwareRules(unittest.TestCase):
    def cat(self, text):
        m = rules.match_software(text)
        return m[0] if m else None

    def test_known_programs(self):
        cases = {
            "Steam": "gaming",
            "Epic Games Launcher": "gaming",
            "Docker Desktop": "development",
            "Microsoft Visual Studio Code": "development",
            "Microsoft Visual C++ 2015-2022 Redistributable (x64)": "runtimes",
            "Microsoft Edge WebView2 Runtime": "runtimes",
            "Microsoft Edge": "internet",
            "Google Chrome": "internet",
            "Bitwarden": "security",
            "NVIDIA Graphics Driver 610.88": "drivers",
            "Realtek Audio Driver": "drivers",
            "VLC media player": "media",
            "Discord": "communication",
            "LibreOffice 24.2": "productivity",
            "7-Zip 24.08 (x64)": "utilities",
            "Dropbox": "cloud",
            "Ollama": "ai",
        }
        for name, want in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.cat(name), want)

    def test_unwanted_and_bloat(self):
        self.assertEqual(self.cat("Driver Booster 11"), "risky")
        self.assertEqual(self.cat("KMSpico"), "risky")
        self.assertEqual(self.cat("uTorrent"), "risky")
        self.assertEqual(self.cat("Logitech Download Assistant"), "bloat")
        self.assertEqual(self.cat("McAfee WebAdvisor"), "bloat")
        # the product itself is security software, its bundled add-on is bloat
        self.assertEqual(self.cat("McAfee Total Protection"), "bloat")
        self.assertEqual(self.cat("Malwarebytes"), "security")

    def test_unknown_is_none(self):
        self.assertIsNone(self.cat("Some Totally Unknown Thing"))

    def test_store_apps(self):
        self.assertEqual(rules.match_store_app("king.com.CandyCrushSaga")[0], "bloat")
        self.assertEqual(rules.match_store_app("Microsoft.WindowsNotepad")[0], "windows")
        self.assertEqual(rules.match_store_app("Microsoft.VCLibs.140.00")[0], "runtimes")
        self.assertIsNone(rules.match_store_app("Contoso.SomeApp"))

    def test_every_category_has_a_group(self):
        groups = {g[0] for g in rules.GROUPS}
        for cat in rules.CATEGORIES:
            self.assertIn(cat[2], groups, cat)
        for cat, _label, _rx in rules.GENERAL_RX:
            self.assertIn(cat, rules.CATEGORY_IDS)


class PathHelpers(unittest.TestCase):
    def test_rel_from_path(self):
        self.assertEqual(rel_from_path("c:\\"), "\\")
        self.assertEqual(rel_from_path("c:\\windows\\system32"), "\\windows\\system32")
        self.assertEqual(rel_from_path("c:\\users\\sam\\appdata\\local"), "~\\appdata\\local")
        self.assertEqual(rel_from_path("d:\\users\\public\\documents"), "\\users\\public\\documents")

    def test_split_command(self):
        self.assertEqual(split_command('"C:\\Program Files\\App\\app.exe" --tray'),
                         ("C:\\Program Files\\App\\app.exe", " --tray"))
        self.assertEqual(split_command("C:\\Program Files\\Docker\\Docker Desktop.exe")[0],
                         "C:\\Program Files\\Docker\\Docker Desktop.exe")
        self.assertEqual(split_command("svchost.exe -k netsvcs")[0], "svchost.exe")

    def test_command_targets_finds_hosted_scripts(self):
        t = command_targets("C:\\Windows\\System32\\rundll32.exe C:\\Users\\x\\AppData\\Roaming\\a.dll,Start")
        self.assertEqual(t[1], "C:\\Users\\x\\AppData\\Roaming\\a.dll")
        t = command_targets('wscript.exe "C:\\Users\\Public\\run.vbs"')
        self.assertIn("C:\\Users\\Public\\run.vbs", t)

    def test_tokens(self):
        self.assertEqual(tokens("EpicInstaller-20.3.3"), {"epic"})
        self.assertIn("vscode", tokens("VSCode"))
        self.assertNotIn("microsoft", tokens("Microsoft Corporation"))


if __name__ == "__main__":
    unittest.main()
