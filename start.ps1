# A3-PS027-TC039 - PowerShell Launcher
Write-Host "Starting A3-PS027-TC039 ..." -ForegroundColor Cyan
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
python "$PSScriptRoot\start.py"
