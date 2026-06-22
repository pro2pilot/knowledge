param(
  [string]$ShortcutPath = "",
  [string]$KnowledgeRoot = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($KnowledgeRoot)) {
  $KnowledgeRoot = Split-Path -Parent $PSScriptRoot
}
$KnowledgeRoot = (Resolve-Path -LiteralPath $KnowledgeRoot).Path

$launcher = Join-Path $KnowledgeRoot "open-inspector.vbs"
if (-not (Test-Path -LiteralPath $launcher)) {
  throw "Missing launcher: $launcher"
}

if ([string]::IsNullOrWhiteSpace($ShortcutPath)) {
  $desktop = [Environment]::GetFolderPath("Desktop")
  $ShortcutPath = Join-Path $desktop "Knowledge Inspector.lnk"
}

$target = Join-Path $env:WINDIR "System32\wscript.exe"

$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($ShortcutPath)
$shortcut.TargetPath = $target
$shortcut.Arguments = "`"$launcher`""
$shortcut.WorkingDirectory = $KnowledgeRoot
$shortcut.WindowStyle = 7
$shortcut.Description = "Open the local .knowledge Inspector"
$shortcut.Save()

Write-Output $ShortcutPath
