param(
  [string]$KnowledgeRoot = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($KnowledgeRoot)) {
  $KnowledgeRoot = Split-Path -Parent $PSScriptRoot
}

function Resolve-KnowledgeRoot {
  param([string]$Root)
  $resolved = (Resolve-Path -LiteralPath $Root).Path
  $directEntry = Join-Path $resolved "inspector.js"
  if (Test-Path -LiteralPath $directEntry) {
    return $resolved
  }
  $nested = Join-Path $resolved ".knowledge"
  $nestedEntry = Join-Path $nested "inspector.js"
  if (Test-Path -LiteralPath $nestedEntry) {
    return (Resolve-Path -LiteralPath $nested).Path
  }
  throw "Missing Inspector entrypoint. Expected $directEntry or $nestedEntry"
}

try {
  $KnowledgeRoot = Resolve-KnowledgeRoot $KnowledgeRoot
} catch {
  [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [System.Windows.Forms.MessageBox]::Show(
    "Inspector did not start.`r`n`r`n$($_.Exception.Message)",
    ".knowledge Inspector",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Error
  )
  exit 1
}
$InspectorEntry = Join-Path $KnowledgeRoot "inspector.js"
$MaintenanceDir = Join-Path $KnowledgeRoot "maintenance"
$LogPath = Join-Path $MaintenanceDir "inspector-launch.log"

function Write-LaunchLog {
  param([string]$Message)
  $timestamp = (Get-Date).ToString("s")
  Add-Content -LiteralPath $LogPath -Value "[$timestamp] $Message"
}

function Resolve-Node {
  $command = Get-Command node -ErrorAction SilentlyContinue
  if ($command -and $command.Source) {
    return $command.Source
  }

  $candidates = @(
    (Join-Path $env:ProgramFiles "nodejs\node.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "nodejs\node.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\nodejs\node.exe")
  ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

  if ($candidates.Count -gt 0) {
    return $candidates[0]
  }

  throw "Node.js was not found. Install Node.js or add node.exe to PATH."
}

try {
  if (-not (Test-Path -LiteralPath $InspectorEntry)) {
    throw "Missing Inspector entrypoint: $InspectorEntry"
  }

  New-Item -ItemType Directory -Force -Path $MaintenanceDir | Out-Null
  $node = Resolve-Node
  Write-LaunchLog "Starting Inspector with node: $node"

  Start-Process -FilePath $node `
    -ArgumentList @($InspectorEntry, "--open") `
    -WorkingDirectory $KnowledgeRoot `
    -WindowStyle Hidden
} catch {
  Write-LaunchLog "Launch failed: $($_.Exception.Message)"
  [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [System.Windows.Forms.MessageBox]::Show(
    "Inspector did not start.`r`n`r`n$($_.Exception.Message)`r`n`r`nLog: $LogPath",
    ".knowledge Inspector",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Error
  )
  exit 1
}
