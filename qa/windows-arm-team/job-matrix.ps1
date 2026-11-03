# QA-only named Job matrix. Input is bounded JSON DATA on stdin; no eval.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class D5HeldMatrix {
  [StructLayout(LayoutKind.Sequential)] struct FILETIME { public uint lo, hi; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out FILETIME c,out FILETIME e,out FILETIME k,out FILETIME u);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint ms);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr p,IntPtr j,out bool member);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  static readonly List<IntPtr> handles=new List<IntPtr>();
  public static string CloseErrors=""; public static int ClosedCount=0;
  static IntPtr Own(IntPtr h,string op) { if(h==IntPtr.Zero) throw new Exception(op+":"+Marshal.GetLastWin32Error()); handles.Add(h); return h; }
  static bool Live(IntPtr h) { uint rc=WaitForSingleObject(h,0); if(rc==0xffffffff)throw new Exception("WaitForSingleObject:"+Marshal.GetLastWin32Error()); if(rc!=0&&rc!=258)throw new Exception("WaitUnexpected:"+rc); return rc==258; }
  static IntPtr Process(uint pid,string birth) {
    ulong expected; if(pid==0 || !UInt64.TryParse(birth,out expected) || expected==0) throw new Exception("identity");
    IntPtr h=Own(OpenProcess(0x00101000,false,pid),"OpenProcess"); FILETIME c,e,k,u;
    if(!GetProcessTimes(h,out c,out e,out k,out u))throw new Exception("GetProcessTimes:"+Marshal.GetLastWin32Error());
    if((((ulong)c.hi<<32)|c.lo)!=expected)throw new Exception("birth_mismatch"); if(!Live(h))throw new Exception("process_exited");
    return h;
  }
  static bool Member(IntPtr p,IntPtr j) { bool member; if(!Live(p))throw new Exception("process_exited_before_query"); if(!IsProcessInJob(p,j,out member))throw new Exception("IsProcessInJob:"+Marshal.GetLastWin32Error()); if(!Live(p))throw new Exception("process_exited_after_query"); return member; }
  public static string[] Check(string job,uint root,string rb,uint selected,string sb,uint secondary,string bb) {
    if(String.IsNullOrEmpty(job)||job.Length>127||!job.StartsWith("Local\\KnowledgeCommand-",StringComparison.Ordinal)) throw new Exception("job_name");
    IntPtr j=Own(OpenJobObject(4,false,job),"OpenJobObject"), r=Process(root,rb), s=Process(selected,sb), b=Process(secondary,bb);
    bool first=Member(r,j), middle=Member(s,j), other=Member(b,j), last=Member(r,j);
    if(!first||!last||other||!Live(s)||!Live(b)) throw new Exception("matrix");
    return new[]{first?"true":"false",middle?"true":"false",other?"true":"false",last?"true":"false"};
  }
  public static bool CloseAll() { bool ok=true; for(int i=handles.Count-1;i>=0;i--) { if(!CloseHandle(handles[i])){ok=false;CloseErrors+=i+":"+Marshal.GetLastWin32Error()+";";} else ClosedCount++; } handles.Clear(); return ok; }
}
'@
$inputText=[Console]::In.ReadToEnd()
if ($inputText.Length -gt 65536) { throw 'request_too_large' }
$req=$inputText | ConvertFrom-Json
if ($req.schema -cne 'knowledge-d5-held-matrix-request.v1' -or @($req.jobs).Count -lt 1 -or @($req.jobs).Count -gt 5) { throw 'request_shape' }
$results=[Collections.Generic.List[object]]::new(); $fault=$null; $closed=$false; $index=0
try {
  foreach ($row in $req.jobs) {
    $v=[D5HeldMatrix]::Check([string]$row.job,[uint32]$row.root.pid,[string]$row.root.birth_filetime,[uint32]$row.selected.pid,[string]$row.selected.birth_filetime,[uint32]$row.secondary.pid,[string]$row.secondary.birth_filetime)
    $results.Add(@{scope_id=[string]$row.scope_id;registered_root=($v[0] -ceq 'true');selected_root=($v[1] -ceq 'true');secondary=($v[2] -ceq 'true');anchor_after=($v[3] -ceq 'true')})
    $index++
  }
} catch { $reason=$_.Exception.GetBaseException().Message; if($reason -cnotmatch '^[A-Za-z_]+(?::[0-9]{1,10})?$'){$reason='unclassified'}; $fault="row${index}:$reason" } finally { $closed=[D5HeldMatrix]::CloseAll() }
if ($fault -or -not $closed -or $results.Count -ne @($req.jobs).Count) { [Console]::Error.WriteLine("matrix_or_close_unconfirmed fault=$fault close_errors=$([D5HeldMatrix]::CloseErrors) closed_count=$([D5HeldMatrix]::ClosedCount)"); exit 1 }
@{schema='knowledge-d5-held-matrix-result.v1';close_all=$true;closed_count=[D5HeldMatrix]::ClosedCount;rows=$results.ToArray()} | ConvertTo-Json -Depth 8 -Compress
