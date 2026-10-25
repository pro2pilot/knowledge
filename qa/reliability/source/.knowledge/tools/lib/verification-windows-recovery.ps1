param([Parameter(Mandatory=$true)][ValidateRange(1,3600000)][long]$CleanupMs,
      [Parameter(Mandatory=$true)][int]$RecovererPid)
$ErrorActionPreference = 'Stop'
$clock = [Diagnostics.Stopwatch]::StartNew()
# All actions use exact opened process handles. A PID, a missing Job name, or a
# timeout alone is never a complete cleanup proof.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KnowledgeNativeRecovery {
  [StructLayout(LayoutKind.Sequential)] public struct Accounting {
    public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
    public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateJobObject(IntPtr job, uint code);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, uint length, IntPtr returnedLength);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateProcess(IntPtr process, uint code);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetProcessTimes(IntPtr handle, out long creation, out long exit, out long kernel, out long user);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
  public static string Birth(IntPtr handle) {
    long creation, exit, kernel, user;
    if (!GetProcessTimes(handle,out creation,out exit,out kernel,out user)) throw new Exception("process_birth_unavailable");
    return DateTime.FromFileTimeUtc(creation).ToString("o");
  }
}
'@
function HostBinding {
  $guid = [Microsoft.Win32.Registry]::GetValue('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography', 'MachineGuid', $null)
  if ([string]::IsNullOrEmpty([string]$guid)) { throw 'native_host_identity_unavailable' }
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
  $hasher = [Security.Cryptography.SHA256]::Create()
  try {
    $hash = { param([string]$value) ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-','').ToLowerInvariant() }
    $normalizedGuid = ([string]$guid).ToLowerInvariant()
    $computer = ([Environment]::MachineName).ToLowerInvariant()
    $machineHash = & $hash $normalizedGuid
    $computerHash = & $hash $computer
    $sidHash = & $hash $sid
    return @{machine_guid_sha256=$machineHash;computer_name_sha256=$computerHash;user_sid_sha256=$sidHash;session_id=$session}
  } finally { $hasher.Dispose() }
}
function RequireHost($expected) {
  $actual = HostBinding
  if ($null -eq $expected) { throw 'native_observer_identity_mismatch' }
  foreach ($key in @('machine_guid_sha256','computer_name_sha256','user_sid_sha256','session_id')) {
    if ($null -eq $expected.$key -or [string]$expected.$key -cne [string]$actual[$key]) { throw 'native_observer_identity_mismatch' }
  }
}
function Remaining {
  return [uint32][Math]::Min([uint32]::MaxValue - 1, [Math]::Max(0, $CleanupMs - $clock.ElapsedMilliseconds))
}
function Emit($value) {
  [Console]::Out.WriteLine(($value | ConvertTo-Json -Compress -Depth 12))
  [Console]::Out.Flush()
}
function OpenExact($identity, [bool]$MayTerminate) {
  if ($null -eq $identity -or [long]$identity.pid -le 0 -or [string]::IsNullOrEmpty([string]$identity.os_creation_time)) { throw 'recovery_identity_invalid' }
  $access = [uint32]0x101000 # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
  if ($MayTerminate) { $access = $access -bor 1 }
  $handle = [KnowledgeNativeRecovery]::OpenProcess($access, $false, [uint32]$identity.pid)
  if ($handle -eq [IntPtr]::Zero) {
    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($code -eq 87) { return @{handle=[IntPtr]::Zero;method='windows_birth_absent';identity=$identity} }
    throw 'recovery_process_open_unconfirmed'
  }
  try {
    $birth = [KnowledgeNativeRecovery]::Birth($handle)
    if ($birth -cne [string]$identity.os_creation_time) {
      [KnowledgeNativeRecovery]::CloseHandle($handle) | Out-Null
      return @{handle=[IntPtr]::Zero;method='windows_birth_absent';identity=$identity}
    }
    return @{handle=$handle;method='process_handle_signaled';identity=$identity}
  } catch {
    [KnowledgeNativeRecovery]::CloseHandle($handle) | Out-Null
    throw
  }
}
function StopExact($opened) {
  if ($opened.handle -eq [IntPtr]::Zero) { return }
  if ([KnowledgeNativeRecovery]::WaitForSingleObject($opened.handle, 0) -eq 0) { return }
  if ([long]$opened.identity.pid -eq $RecovererPid) { throw 'recovery_refuses_self_termination' }
  $terminateAccepted = [KnowledgeNativeRecovery]::TerminateProcess($opened.handle, 1)
  # Stopping the controller also disconnects the keeper's control pipe. The
  # keeper can enter termination between Wait(0) and TerminateProcess, which
  # may return ERROR_ACCESS_DENIED before its exact handle becomes signaled.
  # Neither return value proves exit; retain this handle and its full wait.
  if ([KnowledgeNativeRecovery]::WaitForSingleObject($opened.handle, (Remaining)) -ne 0) {
    if (-not $terminateAccepted) { throw 'recovery_terminate_unconfirmed' }
    throw 'recovery_process_exit_unconfirmed'
  }
}
$job = [IntPtr]::Zero
$opened = @()
try {
  $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
  if ($request.action -eq 'identity') {
    $handle = [KnowledgeNativeRecovery]::OpenProcess(0x101000, $false, [uint32]$RecovererPid)
    if ($handle -eq [IntPtr]::Zero) { throw 'recovery_owner_identity_unavailable' }
    try { Emit @{status='identified';identity=@{backend='windows_process';pid=$RecovererPid;os_creation_time=[KnowledgeNativeRecovery]::Birth($handle);host=(HostBinding)}} }
    finally { [KnowledgeNativeRecovery]::CloseHandle($handle) | Out-Null }
    exit 0
  }
  if ($request.action -eq 'verify_exit') {
    RequireHost $request.identity.host
    $target = OpenExact $request.identity $false
    $opened += $target
    if ($target.handle -eq [IntPtr]::Zero -or [KnowledgeNativeRecovery]::WaitForSingleObject($target.handle,0) -eq 0) {
      Emit @{status='exited';method=$target.method}
    } else { Emit @{status='active'} }
    exit 0
  }
  if ($request.action -ne 'recover' -and $request.action -ne 'query_scope') { throw 'recovery_action_invalid' }
  if ([string]$request.descriptor_sha256 -notmatch '^[a-f0-9]{64}$') { throw 'recovery_descriptor_invalid' }
  $descriptor = $request.descriptor
  if ($descriptor.schema_version -ne 'knowledge-windows-job.v1' -or $descriptor.backend -ne 'windows_job_object' -or
      [string]$descriptor.job_name -notmatch '^Local\\KnowledgeVerification-[a-f0-9]{64}$') { throw 'recovery_descriptor_invalid' }
  RequireHost $descriptor.host
  if ($request.action -eq 'query_scope') {
    $job = [KnowledgeNativeRecovery]::OpenJobObject(0x0004, $false, [string]$descriptor.job_name) # QUERY only
    if ($job -eq [IntPtr]::Zero) { throw 'recovery_job_reopen_unconfirmed' }
    $worker = OpenExact $descriptor.identities.worker $false
    $opened += $worker
    $accounting = New-Object KnowledgeNativeRecovery+Accounting
    if (-not [KnowledgeNativeRecovery]::QueryInformationJobObject($job,1,[ref]$accounting,[Runtime.InteropServices.Marshal]::SizeOf($accounting),[IntPtr]::Zero)) { throw 'recovery_job_query_unconfirmed' }
    if ($accounting.ActiveProcesses -ne 0) {
      Emit @{status='active';method='windows_job_object';descriptor_sha256=$request.descriptor_sha256;job_name=$descriptor.job_name;active_processes=$accounting.ActiveProcesses}
    } elseif ($worker.handle -eq [IntPtr]::Zero -or [KnowledgeNativeRecovery]::WaitForSingleObject($worker.handle,0) -eq 0) {
      Emit @{status='completed';method='windows_job_object';descriptor_sha256=$request.descriptor_sha256;job_name=$descriptor.job_name;active_processes=0;worker_exited=$true;container_proof_basis='retained_named_job'}
    } else { throw 'recovery_worker_exit_unconfirmed' }
    exit 0
  }
  # Hold a real Job handle before stopping its old controller/keeper. Merely
  # failing to reopen a name cannot prove that all kernel references are gone.
  $receipt = $request.cleanup_receipt
  $usingReceipt = $null -ne $receipt
  if ($usingReceipt) {
    if ($receipt.status -ne 'completed' -or $receipt.method -ne 'windows_job_object' -or $receipt.active_processes -ne 0 -or
        $receipt.keeper_exited -ne $true -or $receipt.worker_exited -ne $true -or $receipt.descriptor_sha256 -cne $request.descriptor_sha256 -or
        [string]$request.cleanup_receipt_sha256 -notmatch '^[a-f0-9]{64}$') { throw 'recovery_cleanup_receipt_invalid' }
  } else {
    $job = [KnowledgeNativeRecovery]::OpenJobObject(0x000C, $false, [string]$descriptor.job_name) # QUERY | TERMINATE
    if ($job -eq [IntPtr]::Zero) { throw 'recovery_job_reopen_unconfirmed' }
  }
  foreach ($role in @('controller','keeper','worker')) {
    $target = OpenExact $descriptor.identities.$role ($role -ne 'worker')
    $target.role = $role
    $opened += $target
  }
  StopExact $opened[0]
  StopExact $opened[1]
  if (-not $usingReceipt) {
  if (-not [KnowledgeNativeRecovery]::TerminateJobObject($job,1)) { throw 'recovery_job_terminate_unconfirmed' }
  do {
    $accounting = New-Object KnowledgeNativeRecovery+Accounting
    if (-not [KnowledgeNativeRecovery]::QueryInformationJobObject($job,1,[ref]$accounting,[Runtime.InteropServices.Marshal]::SizeOf($accounting),[IntPtr]::Zero)) { throw 'recovery_job_query_unconfirmed' }
    if ($accounting.ActiveProcesses -eq 0) { break }
    if ((Remaining) -eq 0) { throw 'recovery_job_exit_unconfirmed' }
    Start-Sleep -Milliseconds 20
  } while ((Remaining) -gt 0)
  if ($accounting.ActiveProcesses -ne 0) { throw 'recovery_job_exit_unconfirmed' }
  }
  $worker = $opened[2]
  if ($worker.handle -ne [IntPtr]::Zero -and [KnowledgeNativeRecovery]::WaitForSingleObject($worker.handle,(Remaining)) -ne 0) { throw 'recovery_worker_exit_unconfirmed' }
  $exits = @($opened | ForEach-Object { @{role=$_.role;pid=$_.identity.pid;os_creation_time=$_.identity.os_creation_time;method=$_.method} })
  $basis = 'reopened_named_job'
  if ($usingReceipt) { $basis = 'persisted_native_cleanup_receipt' }
  Emit @{status='completed';method='windows_job_object';descriptor_sha256=$request.descriptor_sha256;job_name=$descriptor.job_name;
    container_proof_basis=$basis;cleanup_receipt_sha256=$request.cleanup_receipt_sha256;active_processes=0;
    keeper_exited=$true;worker_exited=$true;controller_exited=$true;process_exits=$exits}
} catch {
  $code = [string]$_.Exception.Message
  if ($code -notmatch '^[a-z0-9_]{1,128}$') { $code = 'verification_native_recovery_failed' }
  Emit @{status='unconfirmed';code=$code}
  exit 2
} finally {
  foreach ($target in $opened) { if ($target.handle -ne [IntPtr]::Zero) { [KnowledgeNativeRecovery]::CloseHandle($target.handle) | Out-Null } }
  if ($job -ne [IntPtr]::Zero) { [KnowledgeNativeRecovery]::CloseHandle($job) | Out-Null }
}
