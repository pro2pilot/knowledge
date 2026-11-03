param(
  [Parameter(Mandatory=$true)][string]$Archive,
  [Parameter(Mandatory=$true)][string]$ExpectedSha256,
  [Parameter(Mandatory=$true)][string]$Destination,
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [switch]$VerifyExisting
)
# QA wrapper: rejects every .NET ReparsePoint (not merely symlinks/junctions).
# Node parser validates ZIP32 structure, per-member CRC, exact bytes and 119 pins.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Assert-PhysicalChain([string]$Value) {
  if (-not [IO.Path]::IsPathFullyQualified($Value) -or $Value.StartsWith('\\') -or $Value.StartsWith('\\?\') -or
      [IO.Path]::GetFullPath($Value) -cne $Value) { throw 'D5_FS_ABSOLUTE' }
  $current = $Value
  while ($current) {
    $attributes = [IO.File]::GetAttributes($current)
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'D5_FS_REPARSE' }
    $parent = [IO.Path]::GetDirectoryName($current)
    if (-not $parent -or $parent -ceq $current) { break }
    $current = $parent
  }
}
function Assert-PhysicalTree([string]$Root) {
  Assert-PhysicalChain $Root
  $queue = [Collections.Generic.Queue[string]]::new(); $queue.Enqueue($Root); $count = 0
  while ($queue.Count -gt 0) {
    $directory = $queue.Dequeue()
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
      $count++; if ($count -gt 400) { throw 'D5_FS_INVENTORY_LIMIT' }
      $attributes = [IO.File]::GetAttributes($entry)
      if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'D5_FS_REPARSE' }
      if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $queue.Enqueue($entry) }
    }
  }
}
if (-not $IsWindows) { throw 'D5_WINDOWS_VERIFIER_NOT_RUN' }
if ($ExpectedSha256 -cne '24df61b60ff43899a8e85884acf14bef6eb3a8c4a2537413033f5092b6965407') { throw 'D5_INPUT_EXPECTED_PIN' }
Assert-PhysicalChain $Archive; Assert-PhysicalChain $NodeExe
Assert-PhysicalChain ([IO.Path]::GetDirectoryName($Destination))
if ($VerifyExisting) { Assert-PhysicalTree $Destination }
elseif ([IO.File]::Exists($Destination) -or [IO.Directory]::Exists($Destination)) { throw 'D5_FS_FRESH_REQUIRED' }
$mode = if ($VerifyExisting) { 'verify-existing' } else { 'extract' }
$helper = [IO.Path]::Combine($PSScriptRoot,'verify-input.cjs')
Assert-PhysicalChain $helper
# Supervisor redirects this wrapper's whole output to private evidence. Only
# constant status/error codes can originate from the Node CLI.
$process = [Diagnostics.Process]::new()
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $NodeExe; $start.UseShellExecute = $false; $start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
$start.WorkingDirectory = $PSScriptRoot
$start.Environment.Clear()
foreach ($name in @('SystemRoot','WINDIR','SystemDrive','COMSPEC','PATHEXT')) {
  $value = [Environment]::GetEnvironmentVariable($name)
  if ($value) { $start.Environment[$name] = $value }
}
foreach ($argument in @($helper,$mode,$Archive,$Destination)) { $start.ArgumentList.Add($argument) }
$process.StartInfo = $start
try {
  if (-not $process.Start()) { throw 'D5_INPUT_START_FAILED' }
  $null = $process.Handle # Cache our created process handle before any kill.
  $stdoutTask = $process.StandardOutput.ReadToEndAsync(); $stderrTask = $process.StandardError.ReadToEndAsync()
  if (-not $process.WaitForExit(30000)) {
    $process.Kill($false); $null = $process.WaitForExit(2000); throw 'D5_INPUT_DEADLINE'
  }
  if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutTask,$stderrTask),2000)) { throw 'D5_INPUT_PIPE_INCOMPLETE' }
  $captured = $stdoutTask.Result; $exitCode = $process.ExitCode
  if ($captured.Length -gt 4096 -or $stderrTask.Result.Length -gt 4096) { throw 'D5_INPUT_OUTPUT_LIMIT' }
} finally { $process.Dispose() }
if ($exitCode -ne 0) { throw 'D5_INPUT_VERIFIER_FAILED' }
Assert-PhysicalTree $Destination
$value = $captured | ConvertFrom-Json -AsHashtable
if ($value.status -cne 'PASS_SOURCE_TEST_INPUT_INTEGRITY' -or $value.payloads -ne 119 -or $value.members -ne 120) { throw 'D5_INPUT_VERIFIER_RECEIPT' }
$value | ConvertTo-Json -Compress
