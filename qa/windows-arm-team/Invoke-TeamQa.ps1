param(
  [Parameter(Mandatory=$true)][string]$JobRoot,
  [Parameter(Mandatory=$true)][string]$NodeExe,
  [Parameter(Mandatory=$true)][string]$Repository,
  [Parameter(Mandatory=$true)][string]$RunId,
  [Parameter(Mandatory=$true)][string]$RunAttempt,
  [Parameter(Mandatory=$true)][string]$Commit
)
# QA-only supervisor. All subprocess output is private. The outer workflow
# separately captures this entire process, then performs the sole encryption
# and forwards only a validated cipher envelope. This process never encrypts.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$VerbosePreference='SilentlyContinue'
$DebugPreference='SilentlyContinue'
$WarningPreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
Set-StrictMode -Version Latest
$clock=[Diagnostics.Stopwatch]::StartNew()
$utf8=[Text.UTF8Encoding]::new($false,$true)
$inputSha='24df61b60ff43899a8e85884acf14bef6eb3a8c4a2537413033f5092b6965407'
$keyId='a7b0e9a0f1fe0a908da8aa9798dc4d8a9d2cec7526015e67aaa0989dcb30356b'
$private=$null; $helpers=$null; $owned=$null; $source=$null; $pwsh=$null
$childEnv=$null; $keyVerified=$false; $sourceStarted=$false; $analysis=$null; $analysisComplete=$false; $requestReady=$false
$phases=[Collections.Generic.List[object]]::new()
$commands=[Collections.Generic.List[object]]::new()
$product=[ordered]@{started=$false;exited=$false;original_child_exit=$null;timed_out=$false;overflow=$false;
  stdout_eof=$false;stderr_eof=$false;pipe_failure=$false;kill_attempted=$false;kill_succeeded=$false;
  retained_handle_captured=$false;stdout_observed_bytes=0;stderr_observed_bytes=0;elapsed_ms=0;capture_elapsed_ms=0;failure_code=$null}
$state=[ordered]@{schema='knowledge-d5-supervisor.v1';phase='initial';failure_code=$null;source_after_failure_code=$null;product=$product;
  product_deadline_ms=650000;supervisor_soft_budget_ms=740000;teardown_reserve='5s exact-process wait + 2s pipe EOF + 1s cancelled drain';
  scope='WINDOWS_ARM_NODE24_TEAM_QA_ONLY';private_root_preserved=$true;network_isolation='NOT_ESTABLISHED';
  parent_environment_modified=$false;child_environment='EXPLICIT_WINDOWS_ESSENTIALS_PLUS_EXACT_QA_VARIABLES';
  cleanup_basis='Only original native signed terminal and current native exact-birth observations; killing test runner is not Job cleanup';
  os_arch=$null;pwsh_arch=$null;pwsh_version=$PSVersionTable.PSVersion.ToString();
  dotnet_framework=[Runtime.InteropServices.RuntimeInformation]::FrameworkDescription;node_scope=$null;phases=$phases}
$state['snapshot_boundary']='Written after source-after attempt, before analyzer/request; outer supervisor capture and sole encryption occur later'
$result=[ordered]@{status='NOT_RUN';scope='WINDOWS_ARM_NODE24_TEAM_QA_ONLY';product_started=$false;original_child_exit=$null;
  timed_out=$false;overflow=$false;evidence_complete=$false;tests=[ordered]@{expected=2;passed=0;failed=0;skipped=0};
  guard_worker_proof=$false;native_custody_complete=$false;source_unchanged=$false;native_arm_scope_verified=$false;
  details=[ordered]@{root_acceptance='Requires full authenticated reconstruction and independent receipt/raw review';
    branch_instrumentation='Both branches have readonly QA membership/receipt observer; first also has immutable existing custody trace';
    inner_stream_limit='Exact direct test-runner streams; immutable first test separately caps inner CLI capture and trace diagnostic rows';
    original_child_exit_preserved=$true;runner_temp_preserved=$true;export_status='NOT_ATTEMPTED'}}

function Assert-PhysicalChain([string]$Value) {
  if (-not [IO.Path]::IsPathFullyQualified($Value) -or $Value.StartsWith('\\') -or
      [IO.Path]::GetFullPath($Value) -cne $Value -or $Value.Substring(2).Contains(':') -or $Value.Contains('~')) { throw 'D5_PHYSICAL_PATH' }
  $current=$Value
  while ($current) {
    $attrs=[IO.File]::GetAttributes($current)
    if (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'D5_REPARSE_PATH' }
    $next=[IO.Path]::GetDirectoryName($current)
    if (-not $next -or $next -ceq $current) { break }
    $current=$next
  }
}
function New-FreshDirectory([string]$Value) {
  Assert-PhysicalChain ([IO.Path]::GetDirectoryName($Value))
  [D5OwnedDirectory]::CreateFresh($Value)
  Assert-PhysicalChain $Value
}
function Write-PrivateJson([string]$Name,$Value) {
  if ($Name -cnotmatch '^[a-z][a-z0-9.-]*\.json$') { throw 'D5_PRIVATE_NAME' }
  Assert-PhysicalChain $private
  $target=[IO.Path]::Combine($private,$Name)
  $bytes=$utf8.GetBytes(($Value | ConvertTo-Json -Depth 60 -Compress)+"`n")
  if ($bytes.Length -gt 2097152) { throw 'D5_PRIVATE_JSON_BOUND' }
  $stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}
function Read-PrivateJson([string]$Name) {
  $target=[IO.Path]::Combine($private,$Name); Assert-PhysicalChain $target
  if ([IO.FileInfo]::new($target).Length -gt 2097152) { throw 'D5_PRIVATE_JSON_BOUND' }
  return ([IO.File]::ReadAllText($target,$utf8) | ConvertFrom-Json -AsHashtable)
}
function Run-Private([string]$Name,[string]$Executable,[string[]]$Arguments,[int]$Limit,
    [Collections.Generic.Dictionary[string,string]]$Environment,[string]$OutName,[string]$ErrName,[int]$OutCap=2097152) {
  if ($Name -cnotmatch '^[a-z][a-z0-9_-]*$') { throw 'D5_PHASE_NAME' }
  Assert-PhysicalChain $Executable; Assert-PhysicalChain $private
  $available=740000-$clock.ElapsedMilliseconds
  if ($available -lt 1000) { throw 'D5_SUPERVISOR_BUDGET_EXHAUSTED' }
  $bounded=[int][Math]::Max(1,[Math]::Min($Limit,$available))
  $commands.Add([ordered]@{phase=$Name;executable=$Executable;arguments=@($Arguments);timeout_ms=$bounded})
  $receipt=[D5Capture]::Run($Executable,$Arguments,$JobRoot,$Environment,[IO.Path]::Combine($private,$OutName),
    [IO.Path]::Combine($private,$ErrName),$bounded,$OutCap,2097152)
  $phases.Add([ordered]@{name=$Name;started=$receipt.Started;exited=$receipt.Exited;exit_code=$receipt.ExitCode;
    timed_out=$receipt.TimedOut;overflow=$receipt.Overflow;stdout_eof=$receipt.StdoutEof;stderr_eof=$receipt.StderrEof;
    pipe_failure=$receipt.PipeFailure;elapsed_ms=$receipt.ElapsedMs;capture_elapsed_ms=$receipt.CaptureElapsedMs})
  return $receipt
}
function Require-Complete($Receipt,[string]$Failure) {
  if (-not $Receipt.Started -or -not $Receipt.Exited -or $Receipt.ExitCode -ne 0 -or $Receipt.TimedOut -or
      $Receipt.Overflow -or $Receipt.PipeFailure -or -not $Receipt.StdoutEof -or -not $Receipt.StderrEof -or $Receipt.KillAttempted -or
      $Receipt.KillSucceeded -or -not $Receipt.RetainedHandleCaptured -or $null -ne $Receipt.FailureCode -or $Receipt.StderrObservedBytes -ne 0) { throw $Failure }
}
function Clone-Environment([Collections.Generic.Dictionary[string,string]]$Value) {
  $copy=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($entry in $Value.GetEnumerator()) { $copy.Add($entry.Key,$entry.Value) }
  return ,$copy
}

try {
  if ($Repository -cne 'pro2pilot/knowledge' -or $RunId -cnotmatch '^[1-9][0-9]{0,19}$' -or
      $RunAttempt -cnotmatch '^[1-9][0-9]{0,5}$' -or $Commit -cnotmatch '^[0-9a-f]{40}$') { throw 'D5_RUN_BINDING' }
  if (-not $IsWindows) { throw 'D5_WINDOWS_SCOPE_NOT_RUN' }
  Assert-PhysicalChain $JobRoot; Assert-PhysicalChain $NodeExe
  $runnerTemp=[IO.Path]::GetFullPath($env:RUNNER_TEMP)
  Assert-PhysicalChain $runnerTemp
  if (-not $JobRoot.StartsWith($runnerTemp.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or
      [IO.Path]::GetDirectoryName($JobRoot) -ine $runnerTemp.TrimEnd('\') -or $JobRoot -match '\s') { throw 'D5_FRESH_TEMP_SCOPE_NOT_RUN' }
  $helpers=[IO.Path]::Combine($JobRoot,'downloads'); Assert-PhysicalChain $helpers
  $pwsh=[Environment]::ProcessPath; Assert-PhysicalChain $pwsh
  Add-Type -Path ([IO.Path]::Combine($helpers,'supervisor-capture.cs')) -ErrorAction Stop | Out-Null
  $private=[IO.Path]::Combine($JobRoot,'private'); New-FreshDirectory $private
  $observerRegistry=[IO.Path]::Combine($private,'observer-registry'); New-FreshDirectory $observerRegistry
  $owned=[IO.Path]::Combine($JobRoot,'owned-temp'); New-FreshDirectory $owned
  $probeTemp=[IO.Path]::Combine($JobRoot,'native-probe-temp'); New-FreshDirectory $probeTemp
  $preflightTemp=[IO.Path]::Combine($JobRoot,'preflight-temp'); New-FreshDirectory $preflightTemp
  $outside=[IO.Path]::Combine($JobRoot,'preflight-outside'); New-FreshDirectory $outside
  $qaProfile=[IO.Path]::Combine($JobRoot,'user-profile'); New-FreshDirectory $qaProfile
  $appData=[IO.Path]::Combine($qaProfile,'AppData'); New-FreshDirectory $appData
  $localAppData=[IO.Path]::Combine($appData,'Local'); New-FreshDirectory $localAppData
  $roaming=[IO.Path]::Combine($appData,'Roaming'); New-FreshDirectory $roaming
  $source=[IO.Path]::Combine($JobRoot,'source')
  $sourceRoot=[IO.Path]::Combine($source,'runtime','.knowledge')
  $systemRoot=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows); Assert-PhysicalChain $systemRoot
  $system32=[IO.Path]::Combine($systemRoot,'System32'); Assert-PhysicalChain $system32
  $childEnv=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($pair in @(@('SystemRoot',$systemRoot),@('WINDIR',$systemRoot),@('SystemDrive',[IO.Path]::GetPathRoot($systemRoot).TrimEnd('\')),
      @('ComSpec',[IO.Path]::Combine($system32,'cmd.exe')),@('OS','Windows_NT'),@('PATHEXT','.COM;.EXE;.BAT;.CMD'),
      @('TEMP',$owned),@('TMP',$owned),@('USERPROFILE',$qaProfile),@('APPDATA',$roaming),@('LOCALAPPDATA',$localAppData),
      @('HOMEDRIVE',[IO.Path]::GetPathRoot($qaProfile).TrimEnd('\')),@('HOMEPATH',$qaProfile.Substring(2)),
      @('NUMBER_OF_PROCESSORS',[string][Environment]::ProcessorCount),@('PROCESSOR_ARCHITECTURE','ARM64'))) { $childEnv.Add($pair[0],$pair[1]) }
  # No inherited PATH, HOME, Git config, credential variables, CI/GitHub token,
  # NODE_OPTIONS, NODE_PATH, channel variables or proxy settings reach product.
  $pathParts=[Collections.Generic.List[string]]::new()
  foreach($part in @([IO.Path]::GetDirectoryName($NodeExe),[IO.Path]::GetDirectoryName($pwsh),$system32,$systemRoot)) {
    Assert-PhysicalChain $part; $pathParts.Add($part)
  }
  $gitCmd=[IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),'Git','cmd')
  if ([IO.Directory]::Exists($gitCmd)) { Assert-PhysicalChain $gitCmd; $pathParts.Add($gitCmd) }
  $childEnv.Add('PATH',($pathParts -join ';'))
  $childEnv.Add('KNOWLEDGE_QA_SOURCE_ROOT',$sourceRoot); $childEnv.Add('KNOWLEDGE_QA_PRIVATE_ROOT',$private)
  $childEnv.Add('KNOWLEDGE_QA_OWNED_TEMP',$owned); $childEnv.Add('KNOWLEDGE_QA_GUARD_PROOF',[IO.Path]::Combine($private,'guard-proof.ndjson'))
  $childEnv.Add('KNOWLEDGE_QA_OBSERVER_FILE',[IO.Path]::Combine($private,'observations.ndjson'))
  $childEnv.Add('KNOWLEDGE_QA_OBSERVER_REGISTRY',$observerRegistry)
  $childEnv.Add('KNOWLEDGE_QA_PWSH_EXE',$pwsh)
  $key=[IO.Path]::Combine($helpers,'evidence-public.pem'); Assert-PhysicalChain $key
  if ([IO.FileInfo]::new($key).Length -ne 625 -or -not [D5PublicKey]::Verify([IO.File]::ReadAllBytes($key))) { throw 'D5_PUBLIC_KEY_PIN' }
  $keyVerified=$true
  $state.os_arch=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
  $state.pwsh_arch=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
  $state.phase='node-scope'
  $scopeCode='process.stdout.write(JSON.stringify({platform:process.platform,architecture:process.arch,version:process.version,napi:Number(process.versions.napi),exec_path:process.execPath})+"\n")'
  $scopeRun=Run-Private 'node-scope' $NodeExe @('-e',$scopeCode) 10000 $childEnv 'node-scope.json' 'node-scope.stderr'
  Require-Complete $scopeRun 'D5_NODE_SCOPE_NOT_RUN'
  $node=Read-PrivateJson 'node-scope.json'; $state.node_scope=$node
  if ($state.os_arch -cne 'Arm64' -or $state.pwsh_arch -cne 'Arm64' -or $node.platform -cne 'win32' -or
      $node.architecture -cne 'arm64' -or $node.version -cne 'v24.22.1' -or $node.napi -lt 8 -or
      $node.exec_path -ine $NodeExe) { throw 'D5_NATIVE_ARM_NODE24_SCOPE_NOT_RUN' }
  $state.phase='node-flags'
  $helpRun=Run-Private 'node-help' $NodeExe @('--help') 10000 $childEnv 'node-help.stdout' 'node-help.stderr'
  Require-Complete $helpRun 'D5_NODE_HELP_NOT_RUN'
  $help=[IO.File]::ReadAllText([IO.Path]::Combine($private,'node-help.stdout'),$utf8)
  foreach($flag in @('--test-concurrency','--test-timeout','--test-reporter')) { if (-not $help.Contains($flag)) { throw 'D5_NODE_FLAGS_NOT_RUN' } }
  $state.phase='source-before'
  $archive=[IO.Path]::Combine($helpers,'WINDOWS_TEAM_TEST_INPUT.zip')
  $verifyArgs=@('-NoLogo','-NoProfile','-NonInteractive','-File',[IO.Path]::Combine($helpers,'Verify-TestInput.ps1'),
    '-Archive',$archive,'-ExpectedSha256',$inputSha,'-Destination',$source,'-NodeExe',$NodeExe)
  $beforeRun=Run-Private 'source-before' $pwsh $verifyArgs 20000 $childEnv 'source-before.json' 'source-before.stderr'
  Require-Complete $beforeRun 'D5_SOURCE_BEFORE_FAILED'; $sourceStarted=$true
  $state.phase='native-load'
  $probeEnv=Clone-Environment $childEnv
  $probeEnv['TEMP']=$probeTemp; $probeEnv['TMP']=$probeTemp; $probeEnv['KNOWLEDGE_QA_OWNED_TEMP']=$probeTemp
  $nativeRun=Run-Private 'native-load' $NodeExe @([IO.Path]::Combine($helpers,'native-probe.cjs'),$sourceRoot,$probeTemp,$owned) 20000 $probeEnv 'native.json' 'native.stderr'
  Require-Complete $nativeRun 'D5_NATIVE_LOAD_NOT_RUN'
  $native=Read-PrivateJson 'native.json'
  if ($native.status -cne 'PASS_NATIVE_LOAD_SCOPE_ONLY' -or $native.snapshot_disposition.status -cne 'RETAINED_LOADED_DLL_IN_SEPARATE_OWNED_PROBE_ROOT' -or
      $native.snapshot_disposition.cleanup_claimed -ne $false -or $native.probe_temp.directory -cne $probeTemp -or $native.product_temp.directory -cne $owned) { throw 'D5_NATIVE_LOAD_NOT_RUN' }
  $result.native_arm_scope_verified=$true
  $state.phase='guard-preflight'
  $guardEnv=Clone-Environment $childEnv
  $guardEnv['TEMP']=$preflightTemp; $guardEnv['TMP']=$preflightTemp; $guardEnv['KNOWLEDGE_QA_OWNED_TEMP']=$preflightTemp
  $guardEnv.Add('KNOWLEDGE_QA_PREFLIGHT_OUTSIDE',$outside)
  $guardArgs=@('--require',[IO.Path]::Combine($helpers,'guard-recursive-cleanup.cjs'),'--test','--test-concurrency=1','--test-timeout=15000',
    '--test-reporter=tap',[IO.Path]::Combine($helpers,'guard-preflight.test.cjs'))
  $guardRun=Run-Private 'guard-preflight' $NodeExe $guardArgs 20000 $guardEnv 'guard-preflight.stdout' 'guard-preflight.stderr'
  Require-Complete $guardRun 'D5_GUARD_WORKER_PREFLIGHT_NOT_RUN'
  $guardCheck=Run-Private 'guard-proof-check' $NodeExe @([IO.Path]::Combine($helpers,'supervisor-analyze.cjs'),'--guard-preflight',$private,$preflightTemp) 5000 $childEnv 'guard-preflight-check.json' 'guard-preflight-check.stderr'
  Require-Complete $guardCheck 'D5_GUARD_RECEIPT_NOT_RUN'
  $acceptedGuard=Read-PrivateJson 'guard-preflight-check.json'
  if ($acceptedGuard.status -cne 'PASS_ACTUAL_WORKER_GUARD_BEFORE_PRODUCT') { throw 'D5_GUARD_RECEIPT_NOT_RUN' }
  # Preflight's junction/alias fixtures remain in separate preflight-temp. The
  # product root is still an uncontested physical directory with no fixtures.
  Assert-PhysicalChain $owned
  if (@([IO.Directory]::EnumerateFileSystemEntries($owned)).Count -ne 0) { throw 'D5_PRODUCT_TEMP_NOT_EMPTY' }
  [IO.File]::WriteAllBytes([IO.Path]::Combine($private,'observations.ndjson'),[byte[]]::new(0))
  $state.phase='product'
  $productArgs=@('--require',[IO.Path]::Combine($helpers,'guard-recursive-cleanup.cjs'),'--require',[IO.Path]::Combine($helpers,'observe-product.cjs'),
    '--test','--test-concurrency=1','--test-timeout=620000','--test-reporter=tap',[IO.Path]::Combine($sourceRoot,'tests','reliability-windows-team-crash.test.js'))
  $productLimit=[int][Math]::Min(650000,740000-$clock.ElapsedMilliseconds-60000)
  if ($productLimit -lt 620000) { throw 'D5_PRODUCT_FULL_BUDGET_NOT_RUN' }
  $run=Run-Private 'product' $NodeExe $productArgs $productLimit $childEnv 'product.stdout' 'product.stderr'
  $product.started=$run.Started; $product.exited=$run.Exited; $product.original_child_exit=$run.ExitCode
  $product.timed_out=$run.TimedOut; $product.overflow=$run.Overflow; $product.stdout_eof=$run.StdoutEof; $product.stderr_eof=$run.StderrEof
  $product.pipe_failure=$run.PipeFailure; $product.kill_attempted=$run.KillAttempted; $product.kill_succeeded=$run.KillSucceeded
  $product.retained_handle_captured=$run.RetainedHandleCaptured; $product.stdout_observed_bytes=$run.StdoutObservedBytes
  $product.stderr_observed_bytes=$run.StderrObservedBytes; $product.elapsed_ms=$run.ElapsedMs; $product.capture_elapsed_ms=$run.CaptureElapsedMs
  $product.failure_code=$run.FailureCode
} catch {
  $state.failure_code=if ($_.Exception.Message -cmatch '^D5_[A-Z0-9_]+$') { $_.Exception.Message } else { 'D5_SUPERVISOR_PHASE_FAILED' }
} finally {
  # No recursive deletion. Rehash source after every attempted product/native
  # phase, including failures. Unknown cleanup leaves the complete root intact.
  if ($sourceStarted -and $private -and $childEnv -and $clock.ElapsedMilliseconds -lt 710000) {
    try {
      $afterArgs=$verifyArgs+@('-VerifyExisting')
      $afterRun=Run-Private 'source-after' $pwsh $afterArgs 15000 $childEnv 'source-after.json' 'source-after.stderr'
      Require-Complete $afterRun 'D5_SOURCE_AFTER_FAILED'
      $after=Read-PrivateJson 'source-after.json'
      $result.source_unchanged=($after.status -ceq 'PASS_SOURCE_TEST_INPUT_INTEGRITY' -and $after.payloads -eq 119)
    } catch {
      $state.source_after_failure_code='D5_SOURCE_AFTER_UNCONFIRMED'
      if (-not $state.failure_code) { $state.failure_code='D5_SOURCE_AFTER_UNCONFIRMED' }
      $result.source_unchanged=$false
    }
  }
}

# Copy the creator-owned process receipt before any finalization I/O. Even a
# malformed analyzer file must not erase the original child exit or block a
# possible single encrypted partial-evidence export.
$result.product_started=$product.started; $result.original_child_exit=$product.original_child_exit
$result.timed_out=$product.timed_out; $result.overflow=$product.overflow
if ($product.started) {
  $result.status=if ($product.exited -and $null -ne $product.original_child_exit -and $product.original_child_exit -ne 0 -and -not $product.timed_out) { 'FAIL' } else { 'UNCERTAIN' }
}
try {
  if (-not $private -or -not $childEnv) { throw 'D5_PRIVATE_EXPORT_UNAVAILABLE' }
  foreach($name in @('product.stdout','product.stderr')) {
    $file=[IO.Path]::Combine($private,$name)
    if (-not [IO.File]::Exists($file)) { $empty=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); $empty.Dispose() }
  }
  $state.phase='analysis'; Write-PrivateJson 'supervisor.json' $state; Write-PrivateJson 'commands.json' ($commands.ToArray())
  try {
  if ($product.started -and $clock.ElapsedMilliseconds -lt 720000) {
    $analyzeRun=Run-Private 'analysis' $NodeExe @([IO.Path]::Combine($helpers,'supervisor-analyze.cjs'),$private,$sourceRoot) 10000 $childEnv 'analysis.stdout' 'analysis.stderr'
    $analysisProcess=[ordered]@{schema='knowledge-d5-analysis-run.v1';started=$analyzeRun.Started;exited=$analyzeRun.Exited;
      original_child_exit=$analyzeRun.ExitCode;timed_out=$analyzeRun.TimedOut;overflow=$analyzeRun.Overflow;
      stdout_eof=$analyzeRun.StdoutEof;stderr_eof=$analyzeRun.StderrEof;pipe_failure=$analyzeRun.PipeFailure;
      kill_attempted=$analyzeRun.KillAttempted;kill_succeeded=$analyzeRun.KillSucceeded;retained_handle_captured=$analyzeRun.RetainedHandleCaptured;
      stdout_observed_bytes=$analyzeRun.StdoutObservedBytes;stderr_observed_bytes=$analyzeRun.StderrObservedBytes;
      elapsed_ms=$analyzeRun.ElapsedMs;capture_elapsed_ms=$analyzeRun.CaptureElapsedMs;failure_code=$analyzeRun.FailureCode}
    Write-PrivateJson 'analysis-run.json' $analysisProcess
    $result.details['analysis_process']=$analysisProcess
    try { Require-Complete $analyzeRun 'D5_ANALYZER_PROCESS_UNCONFIRMED'; $analysisComplete=$true }
    catch { if (-not $state.failure_code) { $state.failure_code='D5_ANALYZER_PROCESS_UNCONFIRMED' } }
    if ([IO.File]::Exists([IO.Path]::Combine($private,'analysis.json'))) { $analysis=Read-PrivateJson 'analysis.json' }
  }
  if ($analysis) {
    foreach($name in @('guard_worker_proof','native_custody_complete','source_unchanged','native_arm_scope_verified')) { $result[$name]=($analysis[$name] -eq $true) }
    foreach($name in @('passed','failed','skipped')) {
      $count=$analysis.tests[$name]
      if ($count -is [long] -or $count -is [int]) { if ($count -ge 0 -and $count -le 2) { $result.tests[$name]=$count } }
    }
    if ($result.tests.passed+$result.tests.failed+$result.tests.skipped -gt 2) {
      $result.tests.passed=0; $result.tests.failed=0; $result.tests.skipped=0
      $result.details['invalid_tap_count_combination']=$true
    }
    $result.details['analysis_failures']=@($analysis.failures)
    if ($analysis.status -ceq 'PASS_OBSERVATION_CONTRACT' -and $analysisComplete -and -not $state.failure_code -and
        $product.started -and $product.exited -and $product.original_child_exit -eq 0 -and -not $product.timed_out -and
        -not $product.overflow -and -not $product.pipe_failure -and -not $product.kill_attempted -and -not $product.kill_succeeded -and
        $product.retained_handle_captured -and $null -eq $product.failure_code -and $product.elapsed_ms -le 650000 -and
        $product.stdout_eof -and $product.stderr_eof) { $result.status='PASS'; $result.evidence_complete=$true }
  }
  } catch {
    $analysisComplete=$false
    if (-not $state.failure_code) { $state.failure_code='D5_ANALYSIS_FINALIZATION_FAILED' }
    $result.details['analysis_finalization_failure']='D5_ANALYSIS_FINALIZATION_FAILED'
    if ($result.status -ceq 'PASS') { $result.status='UNCERTAIN' }
    $result.evidence_complete=$false
  }
  $result.details['supervisor_failure_code']=$state.failure_code
  $result.details['source_after_failure_code']=$state.source_after_failure_code
  $result.details['stream_overflow_policy']='Capped prefixes retained privately; overflow always evidence_complete=false and never PASS'
  $result.details.export_status='REQUEST_READY_FOR_OUTER_SINGLE_ENCRYPTION'
  # Independent .NET PEM and DER pins are checked a second time immediately
  # before handing off the request. The outer finalizer rechecks the DER pin.
  if (-not $keyVerified -or -not [D5PublicKey]::Verify([IO.File]::ReadAllBytes($key))) { throw 'D5_PUBLIC_KEY_PIN' }
  $files=[Collections.Generic.List[object]]::new(); $omitted=[Collections.Generic.List[string]]::new(); [long]$budget=0
  $known=@('product.stdout','product.stderr','supervisor.json','guard.json','native.json','analysis.json','analysis-run.json','source-before.json','source-after.json',
    'observations.ndjson','guard-proof.ndjson','preflight-proof.ndjson','commands.json','node-scope.json','node-scope.stderr','node-help.stdout','node-help.stderr',
    'source-before.stderr','source-after.stderr','native.stderr','guard-preflight.stdout','guard-preflight.stderr','guard-preflight-check.json','guard-preflight-check.stderr','analysis.stdout','analysis.stderr')
  foreach($name in $known) {
    $file=[IO.Path]::Combine($private,$name)
    if (-not [IO.File]::Exists($file)) { continue }
    Assert-PhysicalChain $file
    $size=[IO.FileInfo]::new($file).Length
    [long]$cost=4*[Math]::Ceiling($size/3.0)+512
    if ($size -gt 2097152 -or $budget+$cost -gt 7800000) { $omitted.Add($name); continue }
    $budget+=$cost
    $kind=if ($name.EndsWith('.stdout') -or $name.EndsWith('.stderr')) { 'stream' } else { 'receipt' }
    $files.Add(@{name=$name;kind=$kind})
  }
  if ($omitted.Count -gt 0) {
    $result.evidence_complete=$false; $result.overflow=$true
    if ($result.status -ceq 'PASS') { $result.status='UNCERTAIN' }
    $result.details['omitted_due_to_transport_bound']=$omitted.ToArray()
  }
  $request=@{schema='knowledge-d5-evidence-request.v1';metadata=@{repository=$Repository;run_id=$RunId;run_attempt=$RunAttempt;commit=$Commit;input_sha256=$inputSha;key_id=$keyId};
    private_root=$private;result=$result;files=$files.ToArray()}
  Write-PrivateJson 'request.json' $request
  $requestReady=$true
} catch {
  if ($result.status -ceq 'PASS') { $result.status='UNCERTAIN' }
}
$summaryStatus=if ($result.status -cin @('PASS','FAIL','NOT_RUN','UNCERTAIN')) { $result.status } else { 'UNCERTAIN' }
[Console]::Out.WriteLine('D5_CANDIDATE '+$summaryStatus+' '+$(if ($requestReady) { 'REQUEST_READY' } else { 'REQUEST_FAILED' }))
if ($requestReady -and $summaryStatus -ceq 'PASS') { exit 0 }
if ($null -ne $product.original_child_exit -and $product.original_child_exit -ne 0) { exit $product.original_child_exit }
exit 75
