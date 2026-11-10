"""Inventory of installed software and things that run: programs, Store apps, services,
drivers, startup entries, scheduled tasks and Windows updates.

Registry data is read directly with winreg. Store apps, services, drivers, tasks and
updates come from one Windows PowerShell call that returns JSON.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import subprocess
import winreg

CATEGORIES = [
    ("program", "Installed programs"),
    ("store_app", "Store & MSIX apps"),
    ("service", "Services"),
    ("driver", "Drivers"),
    ("startup", "Startup entries"),
    ("task", "Scheduled tasks"),
    ("update", "Windows updates"),
]
CATEGORY_LABELS = dict(CATEGORIES)

INVENTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory(
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    name TEXT,
    version TEXT,
    publisher TEXT,
    location TEXT,
    sig TEXT,
    hidden INTEGER DEFAULT 0,
    details TEXT,
    PRIMARY KEY(category, key)
);
"""

UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$out = [ordered]@{}
$out.store_apps = @(Get-AppxPackage | ForEach-Object {
    [pscustomobject]@{ name = $_.Name; family = $_.PackageFamilyName; full = $_.PackageFullName;
        version = [string]$_.Version; publisher = $_.Publisher; location = $_.InstallLocation;
        framework = [bool]$_.IsFramework; kind = [string]$_.SignatureKind; nonremovable = [bool]$_.NonRemovable;
        arch = [string]$_.Architecture }
})
$out.services = @(Get-CimInstance Win32_Service | ForEach-Object {
    [pscustomobject]@{ name = $_.Name; display = $_.DisplayName; path = $_.PathName; start = $_.StartMode;
        state = $_.State; account = $_.StartName; desc = $_.Description }
})
$out.drivers = @(Get-CimInstance Win32_SystemDriver | ForEach-Object {
    [pscustomobject]@{ name = $_.Name; display = $_.DisplayName; path = $_.PathName; start = $_.StartMode;
        state = $_.State }
})
$out.tasks = @(Get-ScheduledTask | ForEach-Object {
    $acts = @($_.Actions | ForEach-Object {
        if ($_.Execute) { (($_.Execute + ' ' + $_.Arguments).Trim()) }
        elseif ($_.ClassId) { 'COM handler ' + $_.ClassId }
    }) -join ' ; '
    $trig = @($_.Triggers | ForEach-Object { ($_.CimClass.CimClassName -replace '^MSFT_Task','' -replace 'Trigger$','') }) -join ', '
    [pscustomobject]@{ path = $_.TaskPath; name = $_.TaskName; state = [string]$_.State; author = $_.Author;
        actions = $acts; triggers = $trig; desc = $_.Description }
})
$out.updates = @(Get-CimInstance Win32_QuickFixEngineering | ForEach-Object {
    $when = ''
    try { if ($_.InstalledOn) { $when = ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') } } catch {}
    [pscustomobject]@{ id = $_.HotFixID; desc = $_.Description; installed = $when }
})
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os = Get-CimInstance Win32_OperatingSystem
$out.os = [pscustomobject]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber;
    ubr = [string]$cv.UBR; display = $cv.DisplayVersion; installed = ([datetime]$os.InstallDate).ToString('yyyy-MM-dd') }
$out | ConvertTo-Json -Depth 4 -Compress
"""


# ---------------------------------------------------------------- registry helpers


def _values(key) -> dict:
    out = {}
    i = 0
    while True:
        try:
            name, value, _type = winreg.EnumValue(key, i)
        except OSError:
            break
        out[name] = value
        i += 1
    return out


def _subkeys(key):
    i = 0
    while True:
        try:
            yield winreg.EnumKey(key, i)
        except OSError:
            return
        i += 1


def _open(hive, path, view=0):
    return winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)


def installed_programs() -> list[dict]:
    sources = [
        ("HKLM64", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, "machine"),
        ("HKLM32", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, "machine (32-bit)"),
        ("HKCU", winreg.HKEY_CURRENT_USER, 0, "current user"),
    ]
    items = []
    for scope, hive, view, scope_label in sources:
        try:
            root = _open(hive, UNINSTALL, view)
        except OSError:
            continue
        with root:
            for sub in _subkeys(root):
                try:
                    with _open(root, sub) as k:
                        v = _values(k)
                except OSError:
                    continue
                name = str(v.get("DisplayName") or "").strip()
                if not name:
                    continue
                version = str(v.get("DisplayVersion") or "").strip()
                release = str(v.get("ReleaseType") or "")
                hidden = bool(v.get("SystemComponent") == 1 or v.get("ParentKeyName")
                              or release.lower() in ("update", "hotfix", "security update"))
                size_kb = v.get("EstimatedSize")
                items.append({
                    "category": "program",
                    "key": f"{scope}\\{sub}",
                    "name": name,
                    "version": version,
                    "publisher": str(v.get("Publisher") or "").strip(),
                    "location": str(v.get("InstallLocation") or "").strip(),
                    "sig": version,
                    "hidden": hidden,
                    "details": {
                        "scope": scope_label,
                        "install_date": str(v.get("InstallDate") or ""),
                        "size_bytes": int(size_kb) * 1024 if isinstance(size_kb, int) else None,
                        "uninstall": str(v.get("UninstallString") or ""),
                        "msi": bool(v.get("WindowsInstaller")),
                        "registry_key": sub,
                    },
                })
    return items


def _startup_approved() -> dict[tuple[str, str], bool]:
    """Task Manager's enable/disable switches for startup entries."""
    out = {}
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
    for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        for sub in ("Run", "Run32", "StartupFolder"):
            try:
                with _open(hive, base + "\\" + sub) as k:
                    for name, data in _values(k).items():
                        if isinstance(data, (bytes, bytearray)) and data:
                            # even first byte = enabled (02/06), odd = disabled (03)
                            out[(hive_name + ":" + sub, name.lower())] = (data[0] & 1) == 0
            except OSError:
                continue
    return out


def startup_entries() -> list[dict]:
    approved = _startup_approved()
    items = []
    run_keys = [
        ("HKCU", winreg.HKEY_CURRENT_USER, 0, r"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
        ("HKCU", winreg.HKEY_CURRENT_USER, 0, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", None),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", None),
        ("HKLM32", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run32"),
        ("HKLM32", winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", None),
    ]
    for scope, hive, view, path, approved_sub in run_keys:
        try:
            with _open(hive, path, view) as k:
                vals = _values(k)
        except OSError:
            continue
        where = f"{scope}\\{path.split(chr(92), 4)[-1]}"
        for name, cmd in vals.items():
            if not name:
                continue
            hive_short = "HKCU" if scope == "HKCU" else "HKLM"
            enabled = approved.get((hive_short + ":" + approved_sub, name.lower()), True) if approved_sub else True
            cmd = str(cmd)
            items.append({
                "category": "startup",
                "key": f"{where}\\{name}",
                "name": name,
                "version": "",
                "publisher": "",
                "location": cmd,
                "sig": f"{cmd}|{'on' if enabled else 'off'}",
                "hidden": False,
                "details": {"where": where, "enabled": enabled},
            })
    folders = [
        ("HKCU", os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "user Startup folder"),
        ("HKLM", os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"), "all-users Startup folder"),
    ]
    for hive_short, folder, label in folders:
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for name in names:
            if name.lower() == "desktop.ini":
                continue
            enabled = approved.get((hive_short + ":StartupFolder", name.lower()), True)
            full = os.path.join(folder, name)
            items.append({
                "category": "startup",
                "key": f"{label}\\{name}",
                "name": name,
                "version": "",
                "publisher": "",
                "location": full,
                "sig": f"{full}|{'on' if enabled else 'off'}",
                "hidden": False,
                "details": {"where": label, "enabled": enabled},
            })
    return items


# ---------------------------------------------------------------- PowerShell sources


def _run_powershell() -> dict:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                       r"System32\WindowsPowerShell\v1.0\powershell.exe")
    encoded = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    proc = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True, timeout=900, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    text = proc.stdout.decode("utf-8", errors="replace").strip()
    start = text.find("{")
    if start < 0:
        raise RuntimeError("PowerShell inventory returned no data: " + proc.stderr.decode("utf-8", "replace")[:500])
    return json.loads(text[start:])


def _windows_dir_prefix() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows").lower()


def _is_microsoft_path(path: str) -> bool:
    p = (path or "").strip().strip('"').lower()
    p = os.path.expandvars(p).lower()
    windir = _windows_dir_prefix()
    return (p.startswith(windir) or p.startswith("\\systemroot\\") or p.startswith("system32\\")
            or p.startswith("\\??\\" + windir) or p.startswith("%systemroot%") or p.startswith("%windir%"))


def from_powershell(data: dict) -> tuple[list[dict], dict]:
    items = []
    for a in data.get("store_apps") or []:
        family = a.get("family") or a.get("name")
        items.append({
            "category": "store_app",
            "key": f"{family}|{a.get('arch') or ''}",
            "name": a.get("name") or family,
            "version": a.get("version") or "",
            "publisher": a.get("publisher") or "",
            "location": a.get("location") or "",
            "sig": a.get("version") or "",
            "hidden": bool(a.get("framework")) or (a.get("kind") == "System"),
            "details": {"kind": a.get("kind"), "framework": a.get("framework"),
                        "nonremovable": a.get("nonremovable"), "package": a.get("full"),
                        "architecture": a.get("arch")},
        })
    for s in data.get("services") or []:
        path = s.get("path") or ""
        items.append({
            "category": "service",
            "key": s.get("name") or "",
            "name": s.get("display") or s.get("name") or "",
            "version": "",
            "publisher": "",
            "location": path,
            "sig": f"{path}|{s.get('start') or ''}|{s.get('account') or ''}",
            "hidden": _is_microsoft_path(path),
            "details": {"service_name": s.get("name"), "start": s.get("start"), "state": s.get("state"),
                        "account": s.get("account"), "description": s.get("desc")},
        })
    for d in data.get("drivers") or []:
        path = d.get("path") or ""
        items.append({
            "category": "driver",
            "key": d.get("name") or "",
            "name": d.get("display") or d.get("name") or "",
            "version": "",
            "publisher": "",
            "location": path,
            "sig": f"{path}|{d.get('start') or ''}",
            "hidden": True,
            "details": {"driver_name": d.get("name"), "start": d.get("start"), "state": d.get("state")},
        })
    for t in data.get("tasks") or []:
        tpath = t.get("path") or "\\"
        enabled = (t.get("state") or "") != "Disabled"
        items.append({
            "category": "task",
            "key": tpath + (t.get("name") or ""),
            "name": t.get("name") or "",
            "version": "",
            "publisher": t.get("author") or "",
            "location": t.get("actions") or "",
            "sig": f"{t.get('actions') or ''}|{'on' if enabled else 'off'}",
            "hidden": tpath.lower().startswith("\\microsoft\\"),
            "details": {"folder": tpath, "state": t.get("state"), "triggers": t.get("triggers"),
                        "description": t.get("desc")},
        })
    for u in data.get("updates") or []:
        if not u.get("id"):
            continue
        items.append({
            "category": "update",
            "key": u["id"],
            "name": u["id"],
            "version": "",
            "publisher": "Microsoft",
            "location": "",
            "sig": "",
            "hidden": False,
            "details": {"description": u.get("desc"), "installed": u.get("installed")},
        })
    return items, data.get("os") or {}


def collect(log=print) -> tuple[list[dict], dict, list[str]]:
    """Return (items, os_info, warnings)."""
    warnings = []
    items: list[dict] = []
    for label, fn in (("installed programs", installed_programs), ("startup entries", startup_entries)):
        try:
            items.extend(fn())
        except Exception as exc:  # keep going; a partial inventory beats none
            warnings.append(f"Could not read {label}: {exc}")
    os_info = {}
    try:
        ps_items, os_info = from_powershell(_run_powershell())
        items.extend(ps_items)
    except Exception as exc:
        warnings.append(f"Could not read Store apps/services/drivers/tasks/updates: {exc}")
    for w in warnings:
        log("  warning: " + w)
    return items, os_info, warnings


def store(con: sqlite3.Connection, items: list[dict]) -> None:
    con.execute(INVENTORY_SCHEMA)
    con.executemany(
        "INSERT OR REPLACE INTO inventory(category, key, name, version, publisher, location, sig, hidden, details)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        [(i["category"], i["key"], i["name"], i["version"], i["publisher"], i["location"], i["sig"],
          1 if i["hidden"] else 0, json.dumps(i["details"], ensure_ascii=False)) for i in items],
    )


_VERSIONISH = re.compile(r"(\bv?\d+([._-]\d+)+\b)|(\(\s*\d+[^)]*\))|(\b\d{2,}\b)")


def normalised_name(name: str) -> str:
    """Program name with version numbers removed, for matching upgrades across keys."""
    s = _VERSIONISH.sub(" ", name.lower())
    return re.sub(r"\s+", " ", s).strip(" -_")
