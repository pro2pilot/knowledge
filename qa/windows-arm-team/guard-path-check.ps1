param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][string]$Target)
# Readonly check; no recursive removal and no host setting changes.
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
try {
  if (-not $IsWindows) { throw 'platform' }
  foreach ($value in @($Root,$Target)) {
    if (-not [IO.Path]::IsPathFullyQualified($value) -or $value.StartsWith('\\') -or [IO.Path]::GetFullPath($value) -cne $value) { throw 'absolute' }
    $chain = [Collections.Generic.List[string]]::new(); $item = $value
    while ($item) { $chain.Add($item); $parent = [IO.Path]::GetDirectoryName($item); if (-not $parent -or $parent -ceq $item) { break }; $item = $parent }
    $chain.Reverse(); $missing = $false
    foreach ($item in $chain) {
      if ($missing) { continue }
      try { $attributes = [IO.File]::GetAttributes($item) }
      catch [IO.FileNotFoundException] { $missing = $true; continue }
      catch [IO.DirectoryNotFoundException] { $missing = $true; continue }
      if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
    }
    if ($value -ceq $Root -and $missing) { throw 'missing_root' }
  }
  if (-not $Target.StartsWith($Root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'containment' }
  if ([IO.Directory]::Exists($Target)) {
    $queue = [Collections.Generic.Queue[string]]::new(); $queue.Enqueue($Target); $count = 0
    while ($queue.Count -gt 0) {
      $directory = $queue.Dequeue()
      foreach ($item in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
        if (++$count -gt 20000) { throw 'limit' }
        $attributes = [IO.File]::GetAttributes($item)
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
        if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $queue.Enqueue($item) }
      }
    }
  }
  [Console]::Out.WriteLine('D5_PHYSICAL_PATH_OK'); exit 0
} catch { [Console]::Error.WriteLine('D5_PHYSICAL_PATH_REJECTED'); exit 1 }
