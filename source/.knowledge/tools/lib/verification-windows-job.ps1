param([Parameter(Mandatory=$true)][int]$WorkerPid, [Parameter(Mandatory=$true)][long]$LifetimeMs, [int]$ControllerPid, [Parameter(Mandatory=$true)][string]$JobName, [string]$ExecutableSha256='')
$ErrorActionPreference = 'Stop'
$lifetime = [Diagnostics.Stopwatch]::StartNew()
$observedExecutableHash = $null
if ($ExecutableSha256 -ne '') {
  $hasher = [Security.Cryptography.SHA256]::Create()
  try {
    $image = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $observedExecutableHash = ([BitConverter]::ToString($hasher.ComputeHash([IO.File]::ReadAllBytes($image)))).Replace('-','').ToLowerInvariant()
    if ($ExecutableSha256 -notmatch '^[a-f0-9]{64}$' -or $observedExecutableHash -ne $ExecutableSha256) { throw 'keeper_executable_changed' }
  } finally { $hasher.Dispose() }
}
# A never-reused named kernel job owns the idle worker. Its durable descriptor
# allows a later recovery process to reopen the same kernel container.
# Descendants inherit membership even after their immediate parent exits.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KnowledgeVerificationJob {
  public static System.Threading.Tasks.Task<string> ReadControl() {
    return System.Threading.Tasks.Task.Factory.StartNew(() => Console.ReadLine(),
      System.Threading.CancellationToken.None, System.Threading.Tasks.TaskCreationOptions.LongRunning,
      System.Threading.Tasks.TaskScheduler.Default);
  }
  [StructLayout(LayoutKind.Sequential)] public struct BasicLimits {
    public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
    public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
    public uint ActiveProcessLimit;
    public UIntPtr Affinity;
    public uint PriorityClass, SchedulingClass;
  }
  [StructLayout(LayoutKind.Sequential)] public struct IoCounters {
    public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
  }
  [StructLayout(LayoutKind.Sequential)] public struct ExtendedLimits {
    public BasicLimits BasicLimitInformation;
    public IoCounters IoInfo;
    public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
  }
  [StructLayout(LayoutKind.Sequential)] public struct Accounting {
    public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
    public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateJobObject(IntPtr attributes, string name);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits info, uint length);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateJobObject(IntPtr job, uint code);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, uint length, IntPtr returnedLength);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetProcessTimes(IntPtr handle, out long creation, out long exit, out long kernel, out long user);
  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
  public static string Birth(IntPtr handle) {
    long creation, exit, kernel, user;
    if (!GetProcessTimes(handle,out creation,out exit,out kernel,out user)) throw new Exception("process_birth_unavailable");
    return DateTime.FromFileTimeUtc(creation).ToString("o");
  }
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
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
$control = [KnowledgeVerificationJob]::ReadControl()
$jobHandle = [IntPtr]::Zero
$processHandle = [IntPtr]::Zero
try {
  if ($control.IsCompleted -or $lifetime.ElapsedMilliseconds -ge $LifetimeMs) { throw 'job_control_expired_before_assignment' }
  if ($JobName -notmatch '^Local\\KnowledgeVerification-[a-f0-9]{64}$') { throw 'job_name_invalid' }
  $jobHandle = [KnowledgeVerificationJob]::CreateJobObject([IntPtr]::Zero, $JobName)
  $createError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($jobHandle -eq [IntPtr]::Zero) { throw 'job_create_failed' }
  if ($createError -eq 183) { throw 'job_name_already_exists' }
  $limits = New-Object KnowledgeVerificationJob+ExtendedLimits
  $basic = New-Object KnowledgeVerificationJob+BasicLimits
  $basic.LimitFlags = 0x00002000 # KILL_ON_JOB_CLOSE; breakaway is not enabled.
  $limits.BasicLimitInformation = $basic
  if (-not [KnowledgeVerificationJob]::SetInformationJobObject($jobHandle, 9, [ref]$limits, [Runtime.InteropServices.Marshal]::SizeOf($limits))) { throw 'job_limits_failed' }
  # Keep the exact process handle, including SYNCHRONIZE, through teardown.
  # TerminateJobObject is a request, not a wait for that process to terminate.
  $processHandle = [KnowledgeVerificationJob]::OpenProcess(0x101101, $false, [uint32]$WorkerPid)
  if ($processHandle -eq [IntPtr]::Zero) { throw 'worker_open_failed' }
  if (-not [KnowledgeVerificationJob]::AssignProcessToJobObject($jobHandle, $processHandle)) { throw 'worker_job_assignment_failed' }
  $controllerHandle = [KnowledgeVerificationJob]::OpenProcess(0x101000, $false, [uint32]$ControllerPid)
  if ($controllerHandle -eq [IntPtr]::Zero) { throw 'controller_open_failed' }
  try {
    $identities = @{worker=@{pid=$WorkerPid;os_creation_time=[KnowledgeVerificationJob]::Birth($processHandle)};
      keeper=@{pid=$PID;os_creation_time=[KnowledgeVerificationJob]::Birth([KnowledgeVerificationJob]::GetCurrentProcess())};
      controller=@{pid=$ControllerPid;os_creation_time=[KnowledgeVerificationJob]::Birth($controllerHandle)}}
  } finally { [KnowledgeVerificationJob]::CloseHandle($controllerHandle) | Out-Null }
  [Console]::Out.WriteLine((@{status='ready';job_name=$JobName;host=(HostBinding);identities=$identities;keeper_executable_sha256=$observedExecutableHash} | ConvertTo-Json -Compress -Depth 4))
  [Console]::Out.Flush()
  while (-not $control.IsCompleted) {
    $left = [Math]::Max(0, $LifetimeMs - $lifetime.ElapsedMilliseconds)
    if ($left -le 0) { throw 'job_control_timeout' }
    $null = $control.Wait([int][Math]::Min([int]::MaxValue, $left))
  }
  $command = $control.Result
  if ($command -ne 'close' -and $command -ne 'drain') { throw 'job_control_disconnected' }
  if (-not [KnowledgeVerificationJob]::TerminateJobObject($jobHandle, 1)) { throw 'job_terminate_failed' }
  do {
    $accounting = New-Object KnowledgeVerificationJob+Accounting
    if (-not [KnowledgeVerificationJob]::QueryInformationJobObject($jobHandle, 1, [ref]$accounting, [Runtime.InteropServices.Marshal]::SizeOf($accounting), [IntPtr]::Zero)) { throw 'job_query_failed' }
    if ($accounting.ActiveProcesses -eq 0) { break }
    Start-Sleep -Milliseconds 20
  } while ($lifetime.ElapsedMilliseconds -lt $LifetimeMs)
  if ($accounting.ActiveProcesses -ne 0) { throw 'job_active_processes_remain' }
  $waitMs = [Math]::Min([uint32]::MaxValue - 1, [Math]::Max(0, $LifetimeMs - $lifetime.ElapsedMilliseconds))
  if ([KnowledgeVerificationJob]::WaitForSingleObject($processHandle, [uint32]$waitMs) -ne 0) { throw 'worker_exit_unconfirmed' }
  if ($command -eq 'drain') {
    # Retain the empty kernel Job until the owner has atomically released its
    # Team lock. A current readonly query can observe ActiveProcesses=0;
    # absence of a Job name remains unconfirmed.
    [Console]::Out.WriteLine('{"status":"drained","active_processes":0}')
    [Console]::Out.Flush()
    $control = [KnowledgeVerificationJob]::ReadControl()
    while (-not $control.IsCompleted) {
      $left = [Math]::Max(0, $LifetimeMs - $lifetime.ElapsedMilliseconds)
      if ($left -le 0) { throw 'job_control_timeout' }
      $null = $control.Wait([int][Math]::Min([int]::MaxValue, $left))
    }
    if ($control.Result -ne 'close') { throw 'job_control_disconnected' }
  }
  [Console]::Out.WriteLine('{"status":"closed","active_processes":0}')
  [Console]::Out.Flush()
} catch {
  [Console]::Out.WriteLine('{"status":"failed"}')
  [Console]::Out.Flush()
  exit 1
} finally {
  if ($processHandle -ne [IntPtr]::Zero) { [KnowledgeVerificationJob]::CloseHandle($processHandle) | Out-Null }
  if ($jobHandle -ne [IntPtr]::Zero) { [KnowledgeVerificationJob]::CloseHandle($jobHandle) | Out-Null }
}
