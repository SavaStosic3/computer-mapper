# Dot-sourced by the launcher scripts. Finds a Python 3.10+ interpreter without needing it on PATH.
function Find-MapperPython {
    $candidates = @()
    if ($env:MAPPER_PYTHON) { $candidates += $env:MAPPER_PYTHON }

    $uv = Get-Command uv -ErrorAction SilentlyContinue
    if (-not $uv) {
        $uvLink = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\uv.exe'
        if (Test-Path $uvLink) { $uv = Get-Item $uvLink }
    }
    if ($uv) {
        $uvPath = if ($uv.Source) { $uv.Source } else { $uv.FullName }
        $found = & $uvPath python find '>=3.10' 2>$null
        if ($LASTEXITCODE -eq 0 -and $found) { $candidates += ($found | Select-Object -First 1).Trim() }
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        $found = & $py.Source -3 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $found) { $candidates += $found.Trim() }
    }
    foreach ($c in (Get-Command python, python3 -All -ErrorAction SilentlyContinue)) {
        # skip the Microsoft Store placeholder that only opens the Store
        if ($c.Source -and $c.Source -notlike '*\WindowsApps\*') { $candidates += $c.Source }
    }

    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) {
            $ok = & $c -c "import sys; print(sys.version_info >= (3, 10))" 2>$null
            if ($ok -eq 'True') { return $c }
        }
    }
    throw "Python 3.10 or newer was not found. Install one with:  uv python install 3.12   (or from python.org), or set MAPPER_PYTHON to python.exe."
}
