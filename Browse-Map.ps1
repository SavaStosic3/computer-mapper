<#
.SYNOPSIS
    Open the interactive map in your browser: walk every folder, see what changed,
    search file names, list programs. Close this window (or press Ctrl+C) to stop it.
#>
param([int]$Port = 8765)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'mapper\find-python.ps1')
Set-Location $PSScriptRoot
$python = Find-MapperPython
& $python -m mapper browse --port $Port
