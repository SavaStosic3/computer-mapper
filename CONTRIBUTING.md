# Contributing

Thanks for helping. Computer Mapper is small on purpose, and a few rules keep it trustworthy:

- **Read-only.** The scan records names, sizes, dates and attributes. It never opens, changes or
  deletes your files, and the browser view never deletes anything either.
- **Local-only.** No network access, no telemetry, no uploads.
- **Standard library only.** Python 3.10+ on Windows, nothing to `pip install`.

## Never share your scan data

`data\` and `reports\` hold a complete map of your PC: file names, folders, installed programs, your
user name. They're in `.gitignore`. Don't attach snapshots or reports to issues; describe the problem
or paste a few relevant lines with personal names removed.

## The easiest contribution: better rules

Categories and cleanup suggestions come from plain data in [`mapper/rules.py`](mapper/rules.py):

- **A program or folder gets the wrong category?** Add or adjust a pattern in `GENERAL`, `FOLDERS`,
  `FOLDER_TAILS` or `STORE_APPS`. Rules are tried in order and the first match wins.
- **Bloat that isn't flagged?** Add it to `BLOAT` with a confidence and a one-sentence note saying why
  most people don't need it.
- **Potentially unwanted software?** Add it to `RISKY` only if it's widely flagged (for example by
  Microsoft Defender or major antivirus vendors), and keep the note factual.

Please add a case to [`tests/test_rules.py`](tests/test_rules.py) for anything you add.

## Running the tests

```powershell
python -m unittest discover -s tests -t . -v
```

The tests never touch your real data: they build a fake PC in a temporary folder
([`tests/fake_pc.py`](tests/fake_pc.py)) and scan small temporary folders.

To try the viewer against throwaway data, point it somewhere else first:

```powershell
$env:MAPPER_DATA_DIR = "$env:TEMP\cm-data"; $env:MAPPER_REPORT_DIR = "$env:TEMP\cm-reports"
python -m mapper scan --roots C:\Windows\Web --no-open
python -m mapper browse
```

## Layout

| File | What it does |
|---|---|
| `mapper/fsscan.py` | walks the drives into a SQLite snapshot |
| `mapper/inventory.py` | programs, Store apps, services, drivers, startup entries, tasks, updates |
| `mapper/diff.py` | compares two snapshots |
| `mapper/rules.py` | what the classifier knows (categories, software and folder rules) |
| `mapper/classify.py` | tags every folder and program with a category |
| `mapper/cleanup.py` | finds cleanup suggestions |
| `mapper/report.py` | the self-contained HTML report |
| `mapper/viewer.py`, `mapper/static/viewer.html` | the local browser view |
