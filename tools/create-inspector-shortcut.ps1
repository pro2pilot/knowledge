param(
  [string]$ShortcutPath = "",
  [string]$KnowledgeRoot = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($KnowledgeRoot)) {
  $KnowledgeRoot = Split-Path -Parent $PSScriptRoot
}

function Resolve-KnowledgeRoot {
  param([string]$Root)
  $resolved = (Resolve-Path -LiteralPath $Root).Path
  $directLauncher = Join-Path $resolved "open-inspector.vbs"
  $directEntry = Join-Path $resolved "inspector.js"
  if ((Test-Path -LiteralPath $directLauncher) -and (Test-Path -LiteralPath $directEntry)) {
    return $resolved
  }
  $nested = Join-Path $resolved ".knowledge"
  $nestedLauncher = Join-Path $nested "open-inspector.vbs"
  $nestedEntry = Join-Path $nested "inspector.js"
  if ((Test-Path -LiteralPath $nestedLauncher) -and (Test-Path -LiteralPath $nestedEntry)) {
    return (Resolve-Path -LiteralPath $nested).Path
  }
  throw "Missing Inspector launcher. Expected $directLauncher or $nestedLauncher"
}

$KnowledgeRoot = Resolve-KnowledgeRoot $KnowledgeRoot

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
