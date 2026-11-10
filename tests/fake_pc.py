"""Build a small, made-up snapshot with known problems planted in it.

Nothing here touches the real disk: folders and files only exist as rows in the database.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from mapper import fsscan, inventory

MB = 2 ** 20
HOME = r"C:\Users\bob"
OLD = time.time() - 400 * 86400
NOW = time.time()

# title of each suggestion we expect -> the group it should land in
EXPECTED = {
    "invoice.pdf.exe": "harmful",          # program disguised as a document
    "updater.exe": "harmful",              # program sitting directly in AppData\Roaming
    "cool.scr": "harmful",                 # screensaver file outside Windows
    "KMSpico": "harmful",                  # activation-crack folder
    "Driver Booster 11": "harmful",        # potentially unwanted program
    "Updater": "harmful",                  # startup entry running encoded PowerShell
    "SyncHelper": "harmful",               # task running a program from AppData\Roaming
    "run.vbs": "harmful",                  # script placed directly in the Startup folder
    "Rundll": "harmful",                   # rundll32 loading a DLL from AppData\Roaming
    "McAfee WebAdvisor": "bloat",
    "king.com.CandyCrushSaga": "bloat",
    "GoneApp": "unneeded",                 # startup entry whose program is gone
    "Gone Service": "unneeded",            # service whose program is gone
    "VLC media player": "unneeded",        # registered, but its folder is gone
    "OldVendorThing": "unneeded",          # leftover folder, untouched for over a year
    "VLC-3.0.20-win64.exe": "unneeded",    # old installer in Downloads
    "Recycle Bin on C:": "space",
    "Crash dumps": "space",
    "Your temporary files": "space",
    "Previous Windows installation": "space",
    "node_modules in oldsite": "space",
    "2 copies of movie.mkv": "space",
}

# folders and the category they should get
EXPECTED_CATEGORIES = {
    "C:\\": "windows",
    r"C:\Windows\System32": "windows",
    r"C:\Program Files\KMSpico": "risky",
    r"C:\Program Files\Steam\steamapps\common\SomeGame": "gaming",
    HOME + r"\projects\oldsite": "development",
    HOME + r"\Documents": "personal",
    HOME + r"\AppData\Local\Temp": "junk",
    HOME + r"\AppData\Local\Google\Chrome\User Data\Default": "internet",
    HOME + r"\AppData\Local\Google\Chrome\User Data\Default\Cache": "junk",
    r"C:\Windows.old": "junk",
    r"C:\MyStuff": "personal",
}


class FakePC:
    def __init__(self, db: Path):
        self.db = Path(db)
        if self.db.exists():
            self.db.unlink()
        self.con = fsscan.create_snapshot_db(self.db)
        self.dirs: dict[str, int] = {}

    def mkdir(self, path: str, kind: int = 0) -> int:
        parent = None if path.endswith(":\\") else path.rsplit("\\", 1)[0]
        if parent and parent.endswith(":"):
            parent += "\\"
        if parent and parent not in self.dirs:
            self.mkdir(parent)
        if path in self.dirs:
            return self.dirs[path]
        did = len(self.dirs) + 1
        self.dirs[path] = did
        name = path if parent is None else path.rsplit("\\", 1)[1]
        self.con.execute(
            "INSERT INTO dirs(id, parent, path, name, depth, mtime, kind, files, subdirs, size, tree_files,"
            " tree_dirs, tree_size) VALUES (?,?,?,?,?,?,?,0,0,0,0,0,0)",
            (did, self.dirs.get(parent), path, name, path.count("\\"), OLD, kind))
        return did

    def mkfile(self, path: str, size: int = 1000, mtime: float = OLD) -> None:
        d, name = path.rsplit("\\", 1)
        if d.endswith(":"):
            d += "\\"
        if d not in self.dirs:
            self.mkdir(d)
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        self.con.execute("INSERT INTO files(dir, name, ext, size, mtime, ctime, attrs) VALUES (?,?,?,?,?,?,0)",
                         (self.dirs[d], name, ext, size, mtime, mtime))

    def finish(self, items: list[dict]) -> Path:
        con = self.con
        rows = con.execute("SELECT id, parent FROM dirs ORDER BY id").fetchall()
        for did, size, n in con.execute("SELECT dir, sum(size), count(*) FROM files GROUP BY dir").fetchall():
            con.execute("UPDATE dirs SET size=?, files=?, tree_size=?, tree_files=? WHERE id=?", (size, n, size, n, did))
        for did, parent in reversed(rows):
            if parent:
                con.execute("UPDATE dirs SET tree_size = tree_size + (SELECT tree_size FROM dirs WHERE id=?), "
                            "tree_files = tree_files + (SELECT tree_files FROM dirs WHERE id=?) WHERE id=?",
                            (did, did, parent))
        con.executemany("INSERT INTO meta VALUES (?,?)", [
            ("started", time.strftime("%Y-%m-%dT%H:%M:%S")), ("excluded", "[]"), ("total_size", "0"),
            ("total_files", "0"), ("total_dirs", str(len(rows))), ("computer", "TEST-PC"), ("os", "{}")])
        inventory.store(con, items)
        con.commit()
        con.close()
        return self.db


def build(db: Path) -> Path:
    pc = FakePC(db)
    H = HOME
    pc.mkdir("C:\\")
    for p in [r"C:\Windows\System32", r"C:\Program Files", r"C:\Program Files (x86)", r"C:\ProgramData",
              H + r"\AppData\Roaming", H + r"\AppData\Local\Temp", H + r"\Downloads", H + r"\Documents",
              H + r"\Videos", r"C:\MyStuff"]:
        pc.mkdir(p)
    pc.mkfile(r"C:\pagefile.sys", 8 * MB)
    pc.mkfile(r"C:\Windows\System32\rundll32.exe")
    pc.mkfile(r"C:\Program Files\Steam\steamapps\common\SomeGame\game.exe", 5 * MB, NOW)
    pc.mkfile(H + r"\AppData\Local\Google\Chrome\User Data\Default\Preferences", 1000, NOW)
    pc.mkfile(H + r"\AppData\Local\Google\Chrome\User Data\Default\Cache\data_1", 5 * MB, NOW)
    pc.mkfile(r"C:\MyStuff\notes.txt", 1000, NOW)
    # potentially harmful
    pc.mkfile(H + r"\Downloads\invoice.pdf.exe", 300_000)
    pc.mkfile(H + r"\AppData\Roaming\updater.exe", 500_000)
    pc.mkfile(H + r"\Documents\cool.scr", 200_000)
    pc.mkfile(r"C:\Program Files\KMSpico\KMSELDI.exe", 5 * MB)
    # leftovers: old and unmatched (flagged) vs recently used (not flagged)
    pc.mkfile(r"C:\Program Files (x86)\OldVendorThing\app.exe", 80 * MB)
    pc.mkfile(r"C:\Program Files\FreshVendorThing\x.exe", 80 * MB, NOW)
    # space
    pc.mkfile(H + r"\AppData\Local\Temp\old-setup.tmp", 70 * MB)
    pc.mkfile(H + r"\AppData\Local\Temp\fresh.tmp", 70 * MB, NOW)
    pc.mkfile(H + r"\projects\oldsite\package.json")
    pc.mkfile(H + r"\projects\oldsite\node_modules\react\index.js", 150 * MB)
    pc.mkfile(H + r"\Documents\movie.mkv", 60 * MB, NOW)
    pc.mkfile(H + r"\Videos\movie.mkv", 60 * MB, NOW)
    pc.mkfile(H + r"\Downloads\VLC-3.0.20-win64.exe", 40 * MB)
    pc.mkfile(r"C:\$Recycle.Bin\S-1-5-21\$R123.zip", 900 * MB)
    pc.mkfile(H + r"\AppData\Local\CrashDumps\game.exe.1234.dmp", 300 * MB)
    pc.mkfile(r"C:\Windows.old\Windows\explorer.exe", 900 * MB)

    appdata = os.environ.get("APPDATA", H + r"\AppData\Roaming")
    items = [
        _item("program", "HKLM64\\db", "Driver Booster 11", "IObit", r"C:\Program Files (x86)\IObit\Driver Booster",
              {"uninstall": "x"}),
        _item("program", "HKLM64\\vlc", "VLC media player", "VideoLAN", r"C:\Program Files\VideoLAN\VLC"),
        _item("program", "HKLM64\\wa", "McAfee WebAdvisor", "McAfee, LLC", "",
              {"uninstall": '"C:\\Program Files\\McAfee\\WebAdvisor\\Uninstaller.exe"'}),
        _item("store_app", "king.com.CandyCrushSaga_kgqvnymyfvs32|x64", "king.com.CandyCrushSaga", "CN=King", ""),
        _item("startup", "HKCU\\Run\\Updater", "Updater", "",
              "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi",
              {"where": "HKCU\\Run", "enabled": True}),
        _item("task", "\\SyncHelper", "SyncHelper", "", appdata + r"\updater.exe /silent", {"folder": "\\"}),
        _item("startup", "HKLM\\Run\\GoneApp", "GoneApp", "", r'"C:\Program Files\GoneApp\gone.exe" --tray',
              {"where": "HKLM\\Run", "enabled": True}),
        _item("service", "GoneSvc", "Gone Service", "", r'"C:\Program Files\GoneApp\svc.exe"',
              {"service_name": "GoneSvc", "start": "Auto", "state": "Stopped"}),
        _item("startup", "user Startup folder\\run.vbs", "run.vbs", "",
              appdata + r"\Microsoft\Windows\Start Menu\Programs\Startup\run.vbs",
              {"where": "user Startup folder", "enabled": True}),
        _item("task", "\\Rundll", "Rundll", "", r"C:\Windows\System32\rundll32.exe " + appdata + r"\x.dll,Start",
              {"folder": "\\"}),
        _item("program", "HKLM64\\steam", "Steam", "Valve Corporation", r"C:\Program Files\Steam"),
    ]
    return pc.finish(items)


def _item(category, key, name, publisher, location, details=None):
    return {"category": category, "key": key, "name": name, "version": "", "publisher": publisher,
            "location": location, "sig": "", "hidden": False, "details": details or {}}
