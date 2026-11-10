# Computer Mapper

A complete, private map of your Windows PC: every file, every folder and every installed program,
tagged by what it is, with suggestions for what you can safely remove.

Run a scan once a week or once a month (or let Windows run it for you). Each scan is saved as a
snapshot and compared with the previous one, so you can see exactly what changed: programs installed
or updated, new startup entries, folders that appeared, where your disk space went.

- **Map**: every drive, folder and file with sizes, file counts and dates, browsable in your browser.
- **Changes**: what was added, removed or modified since the last scan, with routine noise (caches,
  logs, temp files) summarized so real changes stand out.
- **Programs & system**: installed programs, Store apps, services, drivers, startup entries, scheduled
  tasks and Windows updates, including version changes.
- **Categories**: everything tagged as Windows, Software, Development, Gaming, Bloat, Cache & temp...
  so you can see what is taking up space.
- **Cleanup suggestions**: things that look unnecessary, like bloat, or potentially harmful, each
  explained and with instructions to remove it yourself.

## Privacy and safety

- **Everything stays on your PC.** No network access, no accounts, no telemetry.
- **Read-only.** The scan records names, sizes, dates and attributes from the folder listings. It never
  opens, changes or deletes your files, and online-only OneDrive files aren't downloaded.
- **Nothing is deleted for you.** Cleanup suggestions tell you why and how; you decide.
- **The browser view is local only.** It listens on `127.0.0.1`, refuses requests from other sites, and
  its few actions (show in Explorer, open a Settings page, hide a suggestion) need a secret token that
  only the page has.
- **Your scan data is personal.** `data\` and `reports\` contain a full list of your files and programs.
  Don't share them.

## Requirements

- Windows 10 or 11
- Python 3.10 or newer, standard library only (nothing to `pip install`). If you don't have it:
  `winget install Python.Python.3.12`. The scripts also find Python installed through `uv` or the `py`
  launcher.

## Getting started

1. Download this repository (green **Code** button › **Download ZIP**, or `git clone`) and extract it
   anywhere, for example `C:\Tools\computer-mapper`.
2. Double-click **`Scan Computer.cmd`**. The first scan becomes your baseline, and a report opens in your
   browser when it's done. A PC with half a million files takes well under a minute.
3. Double-click **`Browse Map.cmd`** to explore the map, categories and cleanup suggestions. Keep its
   small console window open while you browse; close it when you're done.

| To do this | Run |
|---|---|
| Scan now and open the change report | double-click **`Scan Computer.cmd`** (or `.\Scan-Computer.ps1`) |
| Explore the map in your browser | double-click **`Browse Map.cmd`** (or `.\Browse-Map.ps1`) |
| Scan automatically every week or month | `.\Install-ScheduledScan.ps1` |
| Stop the automatic scans | `.\Install-ScheduledScan.ps1 -Remove` |

## Scheduled scans

`Install-ScheduledScan.ps1` creates a Windows Task Scheduler task named
**Computer Mapper - scheduled scan** that scans and opens the report when it finishes. If the PC is off
or asleep at that time, the scan runs the next time you're signed in.

```powershell
.\Install-ScheduledScan.ps1                                    # every Sunday at 00:00 (the default)
.\Install-ScheduledScan.ps1 -DayOfWeek Saturday -Time 09:30    # a different day and time
.\Install-ScheduledScan.ps1 -Every Monthly -Day 1 -Time 12:00  # monthly instead
.\Install-ScheduledScan.ps1 -DryRun                            # show the task without creating it
```

Add `-Elevated` (from an administrator PowerShell) to scan with administrator rights; see
*Good to know*.

## What you get

**The report** (`reports\computer-map-<date>.html`, plus `reports\latest.html`) is a single file you
can open any time, even years later, without the tool. It covers:

- **Programs & system changes**: programs installed, removed and updated (old → new version), Store apps,
  services, drivers, startup entries, scheduled tasks and Windows updates
- **New or changed programs & scripts on disk**: `.exe`, `.dll`, `.msi`, `.ps1`, `.bat` and similar files
  that appeared or changed outside routine areas
- **Where disk space changed**: per drive, and the specific folders that grew or shrank
- **Folders that appeared or disappeared**, each new or removed tree shown once with its totals
- **Changes by area** and the **file-level detail** (added / modified / removed)
- **Cleanup suggestions**
- **The map today**: drives, space by category, biggest folders, space by file type, largest files, and
  the full list of installed programs, startup entries, non-Windows services and scheduled tasks

**The browser view** (`Browse Map.cmd`) has everything from every snapshot:

- **Map**: walk any folder down to individual files, with sizes, counts, dates, each folder's category
  (and why), and how much it changed since the previous scan. *Explorer* opens the real folder.
- **Categories**: space by category, and the folders and programs in each one
- **Cleanup**: suggestions to review, with *Explorer*, *Open Settings* and *Copy command* buttons
- **Changes**: filter added, modified and removed files by type or path, new and removed folders, and the
  biggest space changes
- **Programs**: installed programs, Store apps, services, drivers, startup entries, tasks and updates,
  filterable by category
- **Largest files**, **File types**, **search** by name, and older snapshots via the date menu

## Categories

Every folder and every program, Store app, service, driver, startup entry and scheduled task is tagged
with one category:

| Group | Categories |
|---|---|
| System | **Windows** · **Runtimes & frameworks** (Visual C++, .NET, WebView2: leave these) · **Drivers & hardware** |
| Software | **Security & privacy** · **Development** · **AI tools** · **Browsers & internet** · **Communication** · **Office & productivity** · **Media & creative** · **Cloud, sync & backup** · **Utilities** · **Other software** |
| Gaming | **Gaming** |
| Bloat & risk | **Bloat** (preinstalled extras, promos, trials) · **Potentially unwanted** (adware, fake optimizers, activation cracks) |
| Your files | **Personal files** |
| Cache & temp | **Cache & temp** (caches, temp files, logs, crash dumps, Recycle Bin) |

Tags come from a built-in list of software names, publishers and well-known folders
([`mapper/rules.py`](mapper/rules.py)). A folder that isn't recognised takes its parent's category, so
`C:\Program Files (x86)\Steam\steamapps\common\<game>` is Gaming because of `Steam`. Folders you created
at the top of a drive are Personal files, and anything with a `.git` folder or a project file
(`package.json`, `pyproject.toml`, ...) is Development.

If something is tagged wrong, set it yourself in `config.json` with a folder path or a program's exact
name and one of these category ids: `windows`, `runtimes`, `drivers`, `security`, `development`, `ai`,
`internet`, `communication`, `productivity`, `media`, `cloud`, `utilities`, `software`, `gaming`,
`bloat`, `risky`, `personal`, `junk`, `other`.

```json
"category_overrides": { "D:\\Projects": "development", "Wallpaper Engine": "media" }
```

## Cleanup suggestions

The **Cleanup** tab and a section of each report list things you might want to remove, in four groups:

- **Potentially harmful**: software commonly flagged as potentially unwanted (fake PC optimizers, driver
  updaters, adware browsers, activation cracks...); startup entries, tasks and services that run from
  temporary folders, Downloads or the top of AppData, or that hide what they run (encoded PowerShell,
  mshta, regsvr32 tricks); program files disguised as documents (`invoice.pdf.exe`), screensaver files,
  and programs sitting directly in AppData or ProgramData.
- **Bloat**: preinstalled and promotional apps (Candy Crush, retired Windows apps, PC-maker extras,
  security-suite add-ons, Logitech Download Assistant...).
- **Unnecessary**: startup entries, tasks and services whose program no longer exists; folders left behind
  by software you uninstalled; installers in Downloads for programs that are already installed.
- **Free up space**: the Recycle Bin, old temporary files, crash dumps, Windows upgrade leftovers, big
  caches, `node_modules`/`.venv` folders in projects you haven't touched in months, and duplicate large
  files.

Each suggestion says **why** it was picked, **how sure** it is (high, medium, low) and **how to remove it
yourself**. *Keep* hides a suggestion now and in later scans (stored in `data\cleanup-kept.json`).

Suggestions are worked out from names, locations, dates and sizes; file contents aren't read, so this is
**not an antivirus**. If anything looks harmful, run a full Microsoft Defender scan. Check each suggestion
before acting on it: you know your PC better than a list of rules does.

## Routine churn

Windows and apps rewrite thousands of cache, log and temp files every day. Those changes are still
recorded, but reports summarize them instead of listing them, so real changes stand out. "Routine" covers
temp folders, caches, logs, browser profiles, Windows Update and component stores, `node_modules`, `.git`
internals and database journals. You can change the lists in `config.json`.

## config.json

Created with the defaults on the first scan. Delete it to go back to the defaults.

| Setting | Meaning |
|---|---|
| `roots` | `"auto"` = all fixed drives, or a list such as `["C:\\", "D:\\Projects"]` |
| `include_removable_drives` | also scan USB drives that are plugged in |
| `exclude` | folders to skip entirely (the tool's own `data` and `reports` folders are always skipped) |
| `routine_patterns` | folder patterns treated as routine. `*` matches within one folder name, `**` spans folders |
| `routine_extensions` / `routine_name_suffixes` | file types and name endings treated as routine anywhere |
| `executable_extensions` | file types highlighted as programs & scripts |
| `report_max_rows` | maximum rows per table in the HTML report |
| `space_change_threshold_mb` | minimum folder size change listed under "Where disk space changed" |
| `open_report_after_scan` | open the report in your browser when a scan finishes |
| `category_overrides` | your own categories for folders or programs (see *Categories*) |
| `cleanup` | thresholds for suggestions: smallest cache (`min_cache_mb`) and leftover folder (`min_leftover_mb`) worth listing, how long a project or leftover must be untouched (`idle_days`), smallest duplicate (`duplicate_min_mb`), and how old temp files must be (`temp_age_days`, `min_temp_mb`) |

After changing `category_overrides` or `cleanup`, the browser view re-tags the snapshot the next time
you open it, or run `python -m mapper classify` to refresh the report too.

## Good to know

- **Administrator rights.** As a standard user, a hundred or so protected folders can't be listed
  (System Volume Information, `WindowsApps`, other users' profiles...). They're recorded as unreadable.
  Run the scan from an administrator PowerShell, or schedule it with `-Elevated`, to include most of them.
- **Sizes** add up file sizes the way Explorer's "Size" does. Online-only OneDrive files count at full
  size, and files hard-linked into several folders (common under `C:\Windows\WinSxS`) count in each one,
  so system folders can add up to more than the drive actually uses.
- **Links aren't followed.** Junctions and symbolic links (for example `C:\Documents and Settings`) are
  recorded as links, so nothing is counted twice.
- **"Modified"** means the size or last-modified time changed. File contents aren't hashed.
- **Disk space.** A snapshot takes roughly 120 bytes per file: about 70 MB for a PC with 575,000 files.
  Weekly scans add up to a few GB a year; delete old snapshots from `data\snapshots` whenever you like.
  Reports don't depend on them.

## Command line

The `.ps1` scripts find Python automatically (`MAPPER_PYTHON` overrides it). You can also call the tool
directly:

```
python -m mapper scan [--roots C:\ D:\Projects] [--no-inventory] [--open | --no-open]
python -m mapper classify [snapshot|all]      # re-tag and refresh cleanup suggestions (and the report)
python -m mapper report [snapshot] [--open]   # rebuild a report
python -m mapper compare OLD NEW [--open]     # compare any two snapshots, e.g. a year apart
python -m mapper browse [--port 8765]
python -m mapper list                         # list snapshots
```

`MAPPER_DATA_DIR` and `MAPPER_REPORT_DIR` move the data and reports somewhere else. Data layout:

```
data\snapshots\snapshot-<date>.db   one SQLite database per scan: dirs, files, drives, inventory,
                                    chg_* (changes), cls_* (categories), cleanup (suggestions)
data\cleanup-kept.json              cleanup suggestions you chose to keep
data\logs\scan-<date>.log           scan logs
reports\computer-map-<date>.html    reports
```

## Contributing

Bug reports and better rules are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Tests:

```powershell
python -m unittest discover -s tests -t . -v
```

## License

[MIT](LICENSE). Computer Mapper is provided as is; cleanup suggestions are suggestions, and you are
responsible for what you remove.
