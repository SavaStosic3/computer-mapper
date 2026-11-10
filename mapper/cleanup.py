"""Cleanup suggestions: things that look unnecessary, like bloat, or potentially harmful.

Every finder only reads the snapshot. Suggestions say why an item was picked, how sure we
are (high / medium / low), and how to remove it yourself. Nothing is ever deleted here.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import defaultdict

from . import rules
from .classify import (
    SUSPICIOUS_COMMAND_RX, Ctx, command_targets, normalise_target, ps_quote, rel_from_path, tokens,
)
from .common import file_ext, human_size

GROUPS = [
    ("harmful", "Potentially harmful",
     "Software commonly flagged as unwanted, and programs that start automatically in ways malware often uses."),
    ("bloat", "Bloat", "Preinstalled extras, promotional apps, trials and helpers you probably don't need."),
    ("unneeded", "Unnecessary",
     "Broken startup entries and tasks, leftovers from software that's gone, installers you've already used."),
    ("space", "Free up space", "Recycle Bin, temporary files, crash dumps, caches, old project files and duplicates."),
]
GROUP_IDS = [g[0] for g in GROUPS]
CONF_ORDER = {"high": 0, "medium": 1, "low": 2}

DEFAULTS = {
    "min_cache_mb": 200,
    "min_leftover_mb": 50,
    "idle_days": 90,
    "duplicate_min_mb": 50,
    "temp_age_days": 7,
    "min_temp_mb": 50,
}

RUN_KEYS = {
    "HKCU\\Run": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\RunOnce": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\Run": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\RunOnce": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM32\\Run": "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM32\\RunOnce": "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
}
RUNNABLE_EXTS = {"exe", "com", "scr", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1"}
# folders where a program file sitting *directly* inside is unusual
ODD_EXACT = {
    "~\\appdata\\roaming": "the top of AppData\\Roaming",
    "~\\appdata\\local": "the top of AppData\\Local",
    "~\\appdata\\locallow": "the top of AppData\\LocalLow",
    "\\programdata": "the top of ProgramData",
    "~": "the top of your user folder",
    "\\users\\public": "the Public folder",
}
# trees programs shouldn't start automatically from
ODD_TREES = {
    "~\\appdata\\local\\temp": "a temporary folder",
    "\\windows\\temp": "a temporary folder",
    "~\\downloads": "your Downloads folder",
    "\\$recycle.bin": "the Recycle Bin",
    "\\users\\public": "the Public folder",
}
CRASH_FOLDERS = {
    "~\\appdata\\local\\crashdumps": "Crash dumps",
    "\\windows\\minidump": "Windows crash dumps",
    "\\windows\\livekernelreports": "Windows kernel reports",
    "\\programdata\\microsoft\\windows\\wer": "Windows error reports",
    "~\\appdata\\local\\microsoft\\windows\\wer": "Windows error reports",
}
UPDATE_LEFTOVERS = {
    "\\windows.old": "Previous Windows installation",
    "\\$windows.~bt": "Windows upgrade files",
    "\\$windows.~ws": "Windows upgrade files",
    "\\$getcurrent": "Windows upgrade files",
    "\\$sysreset": "Windows reset leftovers",
    "\\esd": "Windows upgrade files",
}
TEMP_FOLDERS = {"~\\appdata\\local\\temp": "Your temporary files", "\\windows\\temp": "Windows temporary files"}
LEFTOVER_CONTAINERS = {
    "\\program files", "\\program files (x86)", "\\programdata", "~\\appdata\\local", "~\\appdata\\roaming",
    "~\\appdata\\locallow", "~\\appdata\\local\\programs", "\\program files\\common files",
    "\\program files (x86)\\common files",
}
LEFTOVER_SKIP = {
    "microsoft", "packages", "package cache", "temp", "programs", "common files", "windowsapps",
    "installshield installation information", "microsoft.net", "reference assemblies", "msbuild", "windows kits",
    "uninstall information", "internet explorer", "windows nt", "comms", "connecteddevicesplatform", "d3dscache",
    "publishers", "virtualstore", "crashdumps", "squirreltemp", "history", "ssh", "softwaredistribution", "sun",
    "oracle", "java", "modifiablewindowsapps", "windows defender", "windows mail", "windows media player",
    "windows photo viewer", "windows portable devices", "windows security", "windows sidebar", "windowspowershell",
    "desktop", "documents", "start menu", "templates", "application data", "dotnet", "regid.1991-06.com.microsoft",
    "usoshared", "usoprivate", "device stage", "ssh", "intel", "nvidia", "amd",
}
BROWSER_CACHE_NAMES = {"cache", "code cache", "gpucache", "cache_data", "cache2", "shadercache", "dxcache",
                       "d3dscache", "inetcache", "grshadercache", "graphitedawncache", "dawncache", "dawngraphitecache",
                       "dawnwebgpucache", "shared cache"}
INSTALLER_EXTS = {"exe", "msi", "msix", "msixbundle", "appx", "appxbundle"}
ARCHIVE_EXTS = {"zip", "7z", "rar", "iso", "img", "tar", "gz", "tgz", "xz", "bz2", "cab", "dmg"}
DOUBLE_EXT_RX = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|odt|csv|jpe?g|png|gif|bmp|heic|mp3|wav|mp4|avi|mov|mkv|zip|rar|7z|html?)"
    r"\s*\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta)$", re.IGNORECASE)


def _n(n: int, word: str) -> str:
    return f"{n:,} {word}" + ("" if n == 1 else "s")


def _date(ts) -> str:
    try:
        return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d") if ts else "unknown"
    except (OSError, ValueError, OverflowError):
        return "unknown"


def _range(path: str):
    base = path.rstrip("\\") + "\\"
    return {"p": path, "lo": base, "hi": base[:-1] + "]"}


SUBTREE = "(d.path = :p OR (d.path >= :lo AND d.path < :hi))"


class Finder:
    def __init__(self, ctx: Ctx, log):
        self.ctx = ctx
        self.log = log
        self.settings = dict(DEFAULTS)
        self.settings.update({k: v for k, v in (ctx.cfg.get("cleanup") or {}).items() if k in DEFAULTS})
        self.out: dict[str, dict] = {}
        self.covered: list[str] = []      # lower-case paths already explained by a suggestion
        self.broken: set = set()          # inventory items whose program is missing
        self.alive_tokens: set[str] = set()
        self.alive_name_tokens: dict[str, str] = {}   # token -> program name (names/publishers only)
        self.alive_paths: list[str] = []
        self.mb = 2 ** 20

    # ------------------------------------------------------------ plumbing

    def add(self, grp, rule, title, *, target=None, target_type=None, reason="", action="", confidence="medium",
            size=None, count=None, dir_id=None, command=None, settings=None, cat=None, item=None, extra=None):
        key = f"{rule}:{target or title}".lower()
        if key in self.out:
            return
        self.out[key] = {
            "key": key, "grp": grp, "rule": rule, "title": title, "target": target, "target_type": target_type,
            "dir_id": dir_id, "size": size, "count": count, "confidence": confidence, "reason": reason,
            "action": action, "command": command, "settings": settings, "cat": cat,
            "inv_category": item["category"] if item else None, "inv_key": item["key"] if item else None,
            "extra": json.dumps(extra, ensure_ascii=False) if extra else None,
        }
        if target and target_type in ("folder", "file"):
            self.covered.append(target.lower().rstrip("\\"))

    def is_covered(self, path: str) -> bool:
        p = path.lower().rstrip("\\")
        return any(p == c or p.startswith(c + "\\") or c.startswith(p + "\\") for c in self.covered)

    def run(self):
        steps = [self.inventory, self.risky_folders, self.leftovers, self.recycle_bin, self.crash_dumps,
                 self.temp_files, self.update_leftovers, self.caches, self.downloads, self.projects,
                 self.duplicates, self.odd_files]
        for step in steps:
            try:
                step()
            except Exception as exc:  # one finder failing shouldn't hide the others
                self.log(f"  warning: cleanup check '{step.__name__}' failed: {type(exc).__name__}: {exc}")
        return list(self.out.values())

    def files_in(self, path, where="", params=None, order="f.size DESC", limit=None):
        q = (f"SELECT f.dir, d.path, f.name, f.size, f.mtime FROM files f JOIN dirs d ON d.id = f.dir "
             f"WHERE {SUBTREE} {where} ORDER BY {order}" + (f" LIMIT {int(limit)}" if limit else ""))
        return self.ctx.con.execute(q, {**_range(path), **(params or {})}).fetchall()

    def odd_location(self, target: str):
        p = normalise_target(target).lower()
        if "\\" not in p:
            return None
        r = rel_from_path(p.rpartition("\\")[0])
        if r in ODD_EXACT:
            return ODD_EXACT[r]
        for t, label in ODD_TREES.items():
            if r == t or r.startswith(t + "\\"):
                return label
        return None

    # ------------------------------------------------------------ inventory

    def item_action(self, item, broken=False):
        c, d = item["category"], item["details"]
        if c == "program":
            return "Uninstall it in Settings › Apps › Installed apps.", (d.get("uninstall") or None), "apps"
        if c == "store_app":
            return ("Uninstall it in Settings › Apps › Installed apps, or in PowerShell:",
                    f"Get-AppxPackage -Name {ps_quote(item['name'])} | Remove-AppxPackage", "apps")
        if c == "startup":
            where = d.get("where") or ""
            if "Startup folder" in where:
                return ("Turn it off in Settings › Apps › Startup, or delete the shortcut:",
                        f"Remove-Item -LiteralPath {ps_quote(item['location'])}", "startup")
            reg = RUN_KEYS.get(where)
            if reg:
                admin = " (as administrator)" if where.startswith("HKLM") else ""
                return (f"Turn it off in Settings › Apps › Startup, or remove the entry in PowerShell{admin}:",
                        f"Remove-ItemProperty -Path {ps_quote(reg)} -Name {ps_quote(item['name'])}", "startup")
            return "Turn it off in Settings › Apps › Startup.", None, "startup"
        if c == "task":
            return ("Delete or disable it in Task Scheduler, or in PowerShell (as administrator if asked):",
                    f"Unregister-ScheduledTask -TaskPath {ps_quote(d.get('folder') or chr(92))} "
                    f"-TaskName {ps_quote(item['name'])} -Confirm:$false", "tasks")
        if c == "service":
            q = ps_quote(d.get("service_name") or item["key"])
            if broken:
                return "Remove the leftover service from an administrator PowerShell:", f"sc.exe delete {q}", "services"
            return ("Stop it and set it to Disabled in Services, or in an administrator PowerShell:",
                    f"Stop-Service -Name {q}; Set-Service -Name {q} -StartupType Disabled", "services")
        return "", None, None

    def inventory(self):
        ctx = self.ctx
        kinds = {"startup": "Startup entry", "task": "Scheduled task", "service": "Service",
                 "program": "Program", "store_app": "Store app"}
        for item in ctx.items:
            c = item["category"]
            if c in ("update", "driver"):
                continue
            cat, why, match = ctx.item_cat[(c, item["key"])]
            d = item["details"]
            label = kinds.get(c, c)
            if c in ("startup", "task", "service") and not item["hidden"]:
                cmd = item["location"] or ""
                targets = [] if cmd.startswith("COM handler") else command_targets(cmd)
                harm = [msg for rx, msg in SUSPICIOUS_COMMAND_RX if rx.search(cmd)]
                for t in targets:
                    where = self.odd_location(t)
                    if where:
                        harm.append(f"runs {normalise_target(t).rpartition(chr(92))[2]} from {where}")
                if c == "startup" and "Startup folder" in (d.get("where") or "") \
                        and file_ext(item["name"]) in RUNNABLE_EXTS:
                    harm.append("is a program or script placed directly in the Startup folder, where normally only "
                                "shortcuts go")
                if harm:
                    action, command, settings = self.item_action(item)
                    self.add("harmful", "autostart-suspicious", item["name"], target=cmd, target_type=c,
                             confidence="medium", cat=cat, item=item, command=command, settings=settings,
                             reason=f"{label} that {'; '.join(dict.fromkeys(harm))}. Malware often starts this way. "
                                    "If you don't recognise it, scan it with Microsoft Defender before removing it.",
                             action=action)
                    continue
                main = targets[0] if targets else ""
                if main and not main.lower().endswith(".lnk"):
                    if ctx.file_exists(main) is False:
                        self.broken.add((c, item["key"]))
                        action, command, settings = self.item_action(item, broken=True)
                        self.add("unneeded", "broken-autostart", item["name"], target=cmd, target_type=c,
                                 confidence="high", cat=cat, item=item, command=command, settings=settings,
                                 reason=f"{label} that points to {normalise_target(main)}, which no longer exists. "
                                        "It fails every time it runs; the program it belonged to is gone.",
                                 action=action)
                        continue
            if item["hidden"] and c in ("program", "store_app"):
                continue
            if cat == "risky":
                action, command, settings = self.item_action(item)
                note = match[3] if match else ""
                self.add("harmful", "risky-software", item["name"], target=item["key"], target_type=c,
                         confidence="high", cat=cat, item=item, command=command, settings=settings,
                         reason=f"{label} recognised as “{match[1] if match else 'potentially unwanted'}”. {note}".strip(),
                         action=action + " Afterwards, run a Microsoft Defender scan.")
                if item["location"]:
                    self.covered.append(normalise_target(item["location"]).lower().rstrip("\\"))
            elif cat == "bloat":
                action, command, settings = self.item_action(item)
                conf = (match[2] if match else None) or "medium"
                note = (match[3] if match else "") or "Commonly considered bloat."
                self.add("bloat", "bloat", item["name"], target=item["key"], target_type=c, confidence=conf,
                         cat=cat, item=item, command=command, settings=settings,
                         reason=(f"{label} recognised as “{match[1]}”. " if match and match[1] != item["name"]
                                 else f"{label}. ") + note,
                         action=action)
                if item["location"] and c in ("program", "store_app"):
                    self.covered.append(normalise_target(item["location"]).lower().rstrip("\\"))
            elif c == "program" and item["location"]:
                loc = normalise_target(item["location"])
                if ctx.file_exists(loc) is False:
                    self.broken.add((c, item["key"]))
                    action, command, settings = self.item_action(item)
                    self.add("unneeded", "broken-program", item["name"], target=item["key"], target_type=c,
                             confidence="low", cat=cat, item=item, command=command, settings=settings,
                             reason=f"Listed as installed, but its folder {loc} no longer exists. It was probably "
                                    "removed without its uninstaller.",
                             action="Uninstall it in Settings › Apps to clear the entry. If the uninstaller fails, "
                                    "the leftover entry is harmless.")
        # What's still installed and working, for spotting leftovers later. Items suggested for
        # removal don't count: a leftover task shouldn't keep its leftover folder "alive".
        suggested = {(s["inv_category"], s["inv_key"]) for s in self.out.values() if s["inv_category"]}
        for item in ctx.items:
            c = item["category"]
            if c in ("update", "driver") or (c, item["key"]) in self.broken or (c, item["key"]) in suggested:
                continue
            if c in ("service", "task") and item["hidden"]:
                continue
            text = " ".join([item["name"], item["publisher"], item["location"],
                             item["details"].get("uninstall") or "", item["key"] if c == "store_app" else ""])
            self.alive_tokens |= tokens(text)
            if c in ("program", "store_app"):
                for t in tokens(item["name"] + " " + item["publisher"] + " " + (item["key"].split("|")[0]
                                                                                 if c == "store_app" else "")):
                    self.alive_name_tokens.setdefault(t, item["name"])
            for t in ([item["location"]] if c in ("program", "store_app") else command_targets(item["location"])):
                p = normalise_target(t).lower().rstrip("\\")
                if "\\" in p:
                    self.alive_paths.append(p if c in ("program", "store_app") else p.rpartition("\\")[0])
            un = item["details"].get("uninstall") or ""
            if un:
                prog = command_targets(un)
                if prog:
                    self.alive_paths.append(normalise_target(prog[0]).lower().rpartition("\\")[0])

    # ------------------------------------------------------------ folders

    def risky_folders(self):
        ctx = self.ctx
        for row in ctx.dirs:
            did, parent, path = row[0], row[1], row[2]
            if parent is None or ctx.cat[did] != "risky" or ctx.cat.get(parent) == "risky":
                continue
            if self.is_covered(path):
                continue
            label = (ctx.why.get(did) or "").replace("folder name matches ", "")
            note = next((n for lbl, _rx, n in rules.RISKY_RX if lbl == label), "")
            self.add("harmful", "risky-folder", row[3], target=path, target_type="folder", dir_id=did,
                     size=row[6], confidence="high", cat="risky",
                     reason=f"Folder recognised as “{label or 'potentially unwanted software'}”. {note}".strip(),
                     action="Uninstall it in Settings › Apps if it's listed there, then delete this folder and run a "
                            "Microsoft Defender scan.", settings="apps")

    def leftovers(self):
        ctx, s = self.ctx, self.settings
        idle = s["idle_days"] * 86400
        for row in ctx.dirs:
            did, parent, path, name, kind = row[0], row[1], row[2], row[3], row[4]
            if parent is None or kind != 0 or ctx.rel.get(parent) not in LEFTOVER_CONTAINERS:
                continue
            nl = name.lower()
            cat = ctx.cat[did]
            if nl in LEFTOVER_SKIP or ctx.rel[did] in rules.FOLDERS or cat in ("windows", "runtimes", "junk",
                                                                               "personal", "risky"):
                continue
            size = row[6] or 0
            flagged = cat == "bloat"
            if size < (1 if flagged else s["min_leftover_mb"]) * self.mb:
                continue
            newest = ctx.newest.get(did) or row[7] or 0
            if not flagged and newest and ctx.scan_ts - newest < idle:
                continue
            pl = path.lower()
            if any(a == pl or a.startswith(pl + "\\") or pl.startswith(a + "\\") for a in self.alive_paths):
                continue
            toks = tokens(name)
            if not toks or toks & self.alive_tokens:
                continue
            if self.is_covered(path):
                continue
            what = (ctx.why.get(did) or "").replace("folder name matches ", "")
            self.add("unneeded", "leftover", name, target=path, target_type="folder", dir_id=did, size=size,
                     confidence="medium" if flagged else "low", cat=cat,
                     reason=(f"No installed program, service or task matches this folder"
                             f"{' (' + what + ')' if what and what.lower() != nl else ''}, and nothing in it has "
                             f"changed since {_date(newest)}. It's most likely left over from software you removed."),
                     action="Check what it is, then delete the folder. If something breaks, reinstall that program.")

    # ------------------------------------------------------------ space

    def recycle_bin(self):
        ctx = self.ctx
        for row in ctx.dirs:
            if ctx.rel.get(row[0]) != "\\$recycle.bin" or (row[6] or 0) < 10 * self.mb:
                continue
            drive = row[2][:2]
            files = self.files_in(row[2], limit=3)
            count = ctx.con.execute(
                f"SELECT count(*) FROM files f JOIN dirs d ON d.id = f.dir WHERE {SUBTREE}", _range(row[2])).fetchone()[0]
            biggest = ", ".join(f"{f[2]} ({human_size(f[3])})" for f in files)
            self.add("space", "recycle-bin", f"Recycle Bin on {drive}", target=row[2], target_type="folder",
                     dir_id=row[0], size=row[6], count=count, confidence="high", cat="junk",
                     reason=f"{_n(count, 'deleted file')} still taking up space. Largest: {biggest}.",
                     action="Check nothing in it is still needed, then empty the Recycle Bin.",
                     command=f"Clear-RecycleBin -DriveLetter {drive[0]}", settings="recycle")

    def crash_dumps(self):
        ctx = self.ctx
        crash_paths = []
        for row in ctx.dirs:
            r = ctx.rel.get(row[0])
            if r not in CRASH_FOLDERS:
                continue
            crash_paths.append(row[2].lower())
            if row[4] != 0 or (row[6] or 0) < 20 * self.mb:
                continue
            files = self.files_in(row[2])
            progs = defaultdict(int)
            for f in files:
                m = re.match(r"^(.+?\.exe)\.\d+\.dmp$", f[2], re.IGNORECASE)
                if m:
                    progs[m.group(1)] += 1
            top = ", ".join(f"{p} ({n})" for p, n in sorted(progs.items(), key=lambda x: -x[1])[:3])
            self.add("space", "crash-dumps", CRASH_FOLDERS[r], target=row[2], target_type="folder", dir_id=row[0],
                     size=row[6], count=len(files), confidence="high", cat="junk",
                     reason=f"{_n(len(files), 'crash file')}{' from ' + top if top else ''}. They're only useful for "
                            "debugging a crash; nothing needs them.",
                     action="Delete the files in this folder.")
        for did, dpath, name, size, mtime in ctx.con.execute(
                "SELECT f.dir, d.path, f.name, f.size, f.mtime FROM files f JOIN dirs d ON d.id = f.dir "
                "WHERE f.ext = 'dmp' AND f.size >= ? ORDER BY f.size DESC LIMIT 50", (50 * self.mb,)):
            pl = dpath.lower()
            if any(pl == c or pl.startswith(c + "\\") for c in crash_paths) or "\\$recycle.bin" in pl:
                continue
            full = dpath.rstrip("\\") + "\\" + name
            self.add("space", "crash-dump-file", name, target=full, target_type="file", dir_id=did, size=size,
                     confidence="medium", cat="junk",
                     reason=f"Memory dump written after a crash on {_date(mtime)}. Only useful for debugging.",
                     action="Delete the file (Settings › System › Storage › Temporary files can also remove "
                            "system crash dumps).", settings="storage")

    def temp_files(self):
        ctx, s = self.ctx, self.settings
        cutoff = ctx.scan_ts - s["temp_age_days"] * 86400
        for row in ctx.dirs:
            r = ctx.rel.get(row[0])
            if r not in TEMP_FOLDERS or row[4] != 0:
                continue
            old = ctx.con.execute(
                f"SELECT count(*), coalesce(sum(f.size), 0) FROM files f JOIN dirs d ON d.id = f.dir "
                f"WHERE {SUBTREE} AND f.mtime < :cut", {**_range(row[2]), "cut": cutoff}).fetchone()
            if old[1] < s["min_temp_mb"] * self.mb:
                continue
            self.add("space", "temp-files", TEMP_FOLDERS[r], target=row[2], target_type="folder", dir_id=row[0],
                     size=old[1], count=old[0], confidence="high", cat="junk",
                     reason=f"{_n(old[0], 'temporary file')} older than {s['temp_age_days']} days "
                            f"({human_size(old[1])} of the folder's {human_size(row[6])}). Programs leave these "
                            "behind after installs and updates.",
                     action="Use Settings › System › Storage › Temporary files, or delete the folder's contents "
                            "(files in use are skipped).", settings="storage")

    def update_leftovers(self):
        ctx = self.ctx
        for row in ctx.dirs:
            r = ctx.rel.get(row[0])
            if r in UPDATE_LEFTOVERS:
                if row[4] == 0 and (row[6] or 0) < 100 * self.mb:
                    continue
                size = row[6] if row[4] == 0 else None
                self.add("space", "update-leftovers", UPDATE_LEFTOVERS[r], target=row[2], target_type="folder",
                         dir_id=row[0], size=size, confidence="high", cat="junk",
                         reason="Kept after a Windows upgrade so you can roll back. Windows removes it after about "
                                "10 days, but you can remove it sooner if the PC works fine."
                                + ("" if size else " (Its size can only be measured with administrator rights.)"),
                         action="Settings › System › Storage › Temporary files › tick 'Previous Windows "
                                "installation(s)' or 'Windows Update Cleanup'.", settings="storage")
            elif r == "\\windows\\softwaredistribution\\download" and (row[6] or 0) >= 500 * self.mb:
                self.add("space", "update-cache", "Windows Update download cache", target=row[2],
                         target_type="folder", dir_id=row[0], size=row[6], confidence="medium", cat="junk",
                         reason="Update files Windows already installed.",
                         action="Settings › System › Storage › Temporary files › 'Windows Update Cleanup'.",
                         settings="storage")

    def caches(self):
        ctx, s = self.ctx, self.settings
        handled = set(CRASH_FOLDERS) | set(UPDATE_LEFTOVERS) | set(TEMP_FOLDERS) | {"\\$recycle.bin"}
        for row in ctx.dirs:
            did, parent, path, name = row[0], row[1], row[2], row[3]
            if parent is None or ctx.cat[did] != "junk" or ctx.cat.get(parent) == "junk":
                continue
            r = ctx.rel[did]
            if r in handled or r.startswith("\\windows\\") or (row[6] or 0) < s["min_cache_mb"] * self.mb:
                continue
            nl = name.lower()
            pl = path.lower()
            why = ctx.why.get(did) or ""
            command, conf = None, "low"
            if why == "npm package cache" or nl in ("npm-cache", "_cacache"):
                title, command, conf = "npm package cache", "npm cache clean --force", "medium"
            elif pl.endswith("\\pip\\cache"):
                title, command, conf = "pip package cache", "pip cache purge", "medium"
            elif pl.endswith("\\uv\\cache"):
                title, command, conf = "uv package cache", "uv cache clean", "medium"
            elif "yarn" in pl and "cache" in nl:
                title, command, conf = "Yarn package cache", "yarn cache clean", "medium"
            elif "cache" in nl:
                owner = self.owner(did)
                title = f"{owner} › {name}" if owner and owner.lower() != nl else name
                conf = "medium" if nl in BROWSER_CACHE_NAMES else "low"
            elif re.match(r"^logs?$", nl):
                owner = self.owner(did)
                title = f"{owner} › {name}" if owner else name
            else:
                owner = self.owner(did)
                title = f"{owner} › {name}" if owner and owner.lower() != nl else name
            kind = "logs" if re.match(r"^logs?$", nl) else ("temporary files" if nl in ("temp", "tmp") else "cache")
            reason = {
                "cache": "Apps rebuild their caches as needed, so clearing one frees space until it fills up again.",
                "logs": "Old log files. Apps only append to them; deleting them is safe.",
                "temporary files": "Temporary files the app no longer needs.",
            }[kind]
            if command:
                reason = "Package-manager cache: anything deleted is downloaded again when a project needs it."
            self.add("space", "cache", title, target=path, target_type="folder", dir_id=did, size=row[6],
                     count=row[9], confidence=conf, cat="junk", reason=reason,
                     action=("Run the command below, or close the app and delete the folder's contents." if command
                             else "Close the app that uses it, then delete the folder's contents."),
                     command=command)

    def owner(self, did):
        """Name of the app a folder belongs to: the folder under Program Files/AppData/..., or the
        Store app's name; for broad vendor folders (Microsoft, Google) the product folder below it."""
        ctx = self.ctx
        chain = []
        cur = did
        while cur is not None:
            row = ctx.row(cur)
            chain.append(row)
            if row[1] is None:
                return None
            prel = ctx.rel.get(row[1])
            if prel == "~\\appdata\\local\\packages":
                return row[3].split("_")[0]
            if prel in rules.VENDOR_CONTAINERS or prel in ("~\\appdata\\local\\microsoft", "~\\appdata\\roaming\\microsoft"):
                if row[3].lower() in ("microsoft", "google", "packages") and len(chain) >= 2:
                    return chain[-2][3]
                return row[3]
            cur = row[1]
        return None

    def downloads(self):
        ctx, s = self.ctx, self.settings
        roots = [row for row in ctx.dirs if ctx.rel.get(row[0]) == "~\\downloads" and row[4] == 0]
        exts = INSTALLER_EXTS | ARCHIVE_EXTS
        for root in roots:
            for did, dpath, name, size, mtime in self.files_in(root[2]):
                ext = file_ext(name)
                if ext not in exts:
                    continue
                full = dpath.rstrip("\\") + "\\" + name
                age = ctx.scan_ts - (mtime or ctx.scan_ts)
                if ext in INSTALLER_EXTS:
                    stem = re.sub(r"[-_ .]?v?\d[\w.\-]*$", "", name.rsplit(".", 1)[0])
                    hits = [self.alive_name_tokens[t] for t in tokens(stem) if t in self.alive_name_tokens]
                    if hits:
                        self.add("unneeded", "installer-installed", name, target=full, target_type="file",
                                 dir_id=did, size=size, confidence="medium", cat="personal",
                                 reason=f"Installer for {hits[0]}, which is already installed. Programs update "
                                        "themselves, so the installer isn't needed any more.",
                                 action="Delete the file.")
                    elif age > 30 * 86400 and size >= 1 * self.mb:
                        self.add("unneeded", "installer-old", name, target=full, target_type="file", dir_id=did,
                                 size=size, confidence="low", cat="personal",
                                 reason=f"Installer downloaded on {_date(mtime)}. If you already ran it, the file "
                                        "isn't needed.", action="Delete the file if you don't need it again.")
                elif size >= 100 * self.mb and age > s["idle_days"] * 86400:
                    self.add("space", "old-download", name, target=full, target_type="file", dir_id=did, size=size,
                             confidence="low", cat="personal",
                             reason=f"Large download from {_date(mtime)}. If you've already unpacked or used it, "
                                    "the file itself may not be needed.",
                             action="Delete it, or move it to an external drive.")

    def projects(self):
        ctx, s = self.ctx, self.settings
        idle = s["idle_days"] * 86400
        cands = []
        for row in ctx.dirs:
            did, parent, path, name = row[0], row[1], row[2], row[3]
            nl = name.lower()
            if parent is None or nl not in ("node_modules", ".venv", "venv") or row[4] != 0:
                continue
            r = ctx.rel[did]
            parts = r.split("\\")[:-1]
            # skip app internals (AppData, Program Files, editor extensions in dot-folders, nested packages)
            if "\\appdata\\" in r or r.startswith(("\\program files", "\\programdata", "\\windows")) \
                    or "node_modules" in parts or any(p.startswith(".") for p in parts):
                continue
            if ctx.cat.get(parent) not in ("development", "personal", "other"):
                continue
            if (row[6] or 0) < 100 * self.mb:
                continue
            cands.append(row)
        for row in cands:
            did, parent, path, name = row[0], row[1], row[2], row[3]
            newest = ctx.direct_newest.get(parent, 0)
            for (cid, cname) in ctx.con.execute("SELECT id, name FROM dirs WHERE parent = ?", (parent,)):
                if cid != did and cname.lower() not in (".git", "node_modules", ".venv", "venv"):
                    newest = max(newest, ctx.newest.get(cid, 0))
            if not newest or ctx.scan_ts - newest < idle:
                continue
            project = ctx.row(parent)[3]
            restore = ("npm install (or pnpm/yarn install)" if name.lower() == "node_modules"
                       else "uv sync or pip install -r requirements.txt")
            self.add("space", "idle-project", f"{name} in {project}", target=path, target_type="folder",
                     dir_id=did, size=row[6], count=row[9], confidence="medium", cat="development",
                     reason=f"The project hasn't changed since {_date(newest)}. These are downloaded packages, "
                            f"not your code: {restore} brings them back.",
                     action="Delete this folder (only this folder, not the project).")

    def duplicates(self):
        ctx, s = self.ctx, self.settings
        skip_rx = re.compile(r"\\(windows|program files|program files \(x86\)|programdata|\$recycle\.bin)(\\|$)|"
                             r"\\appdata\\|\\node_modules\\|\\\.git\\|site-packages|\\\.venv\\|\\winsxs\\",
                             re.IGNORECASE)
        groups = ctx.con.execute(
            "SELECT name, size, count(*) AS n FROM files WHERE size >= ? GROUP BY name, size HAVING n > 1 "
            "ORDER BY size * (n - 1) DESC LIMIT 400", (s["duplicate_min_mb"] * self.mb,)).fetchall()
        shown = 0
        for name, size, _n in groups:
            places = [(did, p) for did, p in ctx.con.execute(
                "SELECT f.dir, d.path FROM files f JOIN dirs d ON d.id = f.dir WHERE f.name = ? AND f.size = ?",
                (name, size)) if not skip_rx.search(p + "\\")]
            if len(places) < 2:
                continue
            paths = [p.rstrip("\\") + "\\" + name for _d, p in places]
            self.add("space", "duplicate", f"{len(places)} copies of {name}", target=paths[0], target_type="file",
                     dir_id=places[0][0], size=size * (len(places) - 1), count=len(places), confidence="low",
                     cat=ctx.cat.get(places[0][0]),
                     reason=f"Same name and size ({human_size(size)}) in {len(places)} folders. The contents weren't "
                            "compared, so check they really are the same before deleting extras.",
                     action="Keep one copy and delete the others.", extra={"paths": paths[:20]})
            shown += 1
            if shown >= 60:
                break

    # ------------------------------------------------------------ files that look wrong

    def odd_files(self):
        ctx = self.ctx
        exts = sorted(RUNNABLE_EXTS)
        q = ",".join("?" * len(exts))
        for did, name, size, mtime, ext in ctx.con.execute(
                f"SELECT dir, name, size, mtime, ext FROM files WHERE ext IN ({q})", exts):
            r = ctx.rel.get(did, "")
            row = ctx.row(did)
            if row is None:
                continue
            full = row[2].rstrip("\\") + "\\" + name
            if r.startswith("\\windows") and not r.startswith("\\windows\\temp"):
                continue
            noise = "\\node_modules" in r or "site-packages" in r or r.startswith(("\\program files",)) \
                or "\\.git" in r or "\\winsxs" in r
            if DOUBLE_EXT_RX.search(name) and not noise:
                self.add("harmful", "double-extension", name, target=full, target_type="file", dir_id=did,
                         size=size, confidence="medium", cat=ctx.cat.get(did),
                         reason="The name looks like a document or picture, but the real extension makes it a "
                                "program. This is a common way to disguise malware.",
                         action="Don't open it. Scan it with Microsoft Defender (right-click › Scan with Microsoft "
                                "Defender), then delete it.")
            elif ext == "scr" and not noise:
                self.add("harmful", "screensaver-file", name, target=full, target_type="file", dir_id=did,
                         size=size, confidence="medium", cat=ctx.cat.get(did),
                         reason="Screensaver files are programs, and outside the Windows folder they're more often "
                                "malware than screensavers.",
                         action="Scan it with Microsoft Defender, then delete it if you don't know where it came from.")
            elif r in ODD_EXACT and not (r == "~" and ext in ("ps1", "cmd", "bat")):
                self.add("harmful", "odd-location", name, target=full, target_type="file", dir_id=did, size=size,
                         confidence="medium", cat=ctx.cat.get(did),
                         reason=f"A program file sitting directly in {ODD_EXACT[r]} (added {_date(mtime)}). "
                                "Legitimate software installs into its own folder; malware often drops files here.",
                         action="If you don't recognise it, scan it with Microsoft Defender, then delete it.")


def find_all(ctx: Ctx, log) -> list[dict]:
    return Finder(ctx, log).run()
