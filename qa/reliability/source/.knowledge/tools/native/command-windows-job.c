/* N-API 8 Windows command ownership. No compiler or PowerShell is used by a
 * runtime holder. Native threads observe the private control pipe, exact
 * process handles and monotonic lifetime independently of JavaScript I/O. */
#define NAPI_VERSION 8
#define _WIN32_WINNT 0x0602
#define WIN32_LEAN_AND_MEAN
#include <node_api.h>
#include <windows.h>
#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <io.h>
#ifndef KNOWLEDGE_COMMAND_JOB_SOURCE_SHA256
#error "Build must bind the exact Windows job source SHA256"
#endif
#if defined(_M_X64) || defined(__x86_64__)
#define JOB_ARCH "x64"
#elif defined(_M_ARM64) || defined(__aarch64__)
#define JOB_ARCH "arm64"
#else
#error "Unsupported Windows architecture"
#endif

enum { STOP_CONTROL=1, STOP_PARENT=2, STOP_PEER=4, STOP_ROOT=8, STOP_LIFETIME=16, STOP_UNKNOWN=32 };
typedef struct {
  unsigned id; int open, creator, requires_durable;
  HANDLE job, root, parent, peer, shutdown, requested, pipe, control_thread, watch_thread;
  DWORD root_pid, parent_pid, peer_pid;
  unsigned long long root_birth, parent_birth, peer_birth, began, lifetime, cleanup_lifetime;
  volatile LONG64 stop_began;
  volatile LONG stopped, reason, drained, durable, native_error;
} Scope;
/* Handles are never GC owned or recycled into an old numeric token. Each
 * fixed holder creates one scope; the conservative process cap is explicit. */
static Scope scopes[32];
static volatile LONG next_id;

static napi_value str(napi_env env,const char *s) { napi_value v;napi_create_string_utf8(env,s,NAPI_AUTO_LENGTH,&v);return v; }
static void text(napi_env env,napi_value obj,const char *key,const char *s) { napi_set_named_property(env,obj,key,str(env,s)); }
static void number(napi_env env,napi_value obj,const char *key,double d) { napi_value v;napi_create_double(env,d,&v);napi_set_named_property(env,obj,key,v); }
static void boolean(napi_env env,napi_value obj,const char *key,int b) { napi_value v;napi_get_boolean(env,b!=0,&v);napi_set_named_property(env,obj,key,v); }
static napi_value fail(napi_env env,const char *code,DWORD native_error) {
  napi_value error;napi_create_error(env,str(env,code),str(env,code),&error);number(env,error,"native_error",native_error);napi_throw(env,error);return NULL;
}
static int integer(napi_env env,napi_value v,unsigned long long max,unsigned long long *out) {
  double d;napi_valuetype t;if(napi_typeof(env,v,&t)!=napi_ok||t!=napi_number||napi_get_value_double(env,v,&d)!=napi_ok||
    !isfinite(d)||d<1||d>(double)max||floor(d)!=d)return 0;*out=(unsigned long long)d;return 1;
}
static int string(napi_env env,napi_value v,char *out,size_t size) {
  size_t length,used;napi_valuetype t;if(napi_typeof(env,v,&t)!=napi_ok||t!=napi_string||
    napi_get_value_string_utf8(env,v,NULL,0,&length)!=napi_ok||!length||length>=size)return 0;
  return napi_get_value_string_utf8(env,v,out,size,&used)==napi_ok&&used==length&&strlen(out)==length;
}
static int decimal(const char *s,unsigned long long *value) {
  if(!s||!*s||strlen(s)>20||(s[0]=='0'&&s[1]))return 0;unsigned long long n=0;
  for(const char *p=s;*p;p++){if(*p<'0'||*p>'9'||n>(UINT64_MAX-(unsigned)(*p-'0'))/10)return 0;n=n*10+(unsigned)(*p-'0');}
  if(!n)return 0;*value=n;return 1;
}
static unsigned long long birth(HANDLE h) {
  FILETIME c,e,k,u;if(!GetProcessTimes(h,&c,&e,&k,&u))return 0;
  return ((unsigned long long)c.dwHighDateTime<<32)|c.dwLowDateTime;
}
static napi_value identity(napi_env env,DWORD pid,unsigned long long created) {
  napi_value obj;napi_create_object(env,&obj);char value[32];snprintf(value,sizeof(value),"%llu",created);
  number(env,obj,"pid",pid);text(env,obj,"birth_filetime",value);return obj;
}
static int identity_arg(napi_env env,napi_value value,DWORD *pid,unsigned long long *created) {
  napi_value p,b;unsigned long long n;char s[32];
  if(napi_get_named_property(env,value,"pid",&p)!=napi_ok||!integer(env,p,0xffffffffu,&n)||
    napi_get_named_property(env,value,"birth_filetime",&b)!=napi_ok||!string(env,b,s,sizeof(s))||!decimal(s,created))return 0;
  *pid=(DWORD)n;return 1;
}
static int signaled(HANDLE h) { return h&&WaitForSingleObject(h,0)==WAIT_OBJECT_0; }
static HANDLE exact_process(DWORD pid,unsigned long long expected,DWORD extra) {
  HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE|extra,FALSE,pid);
  if(!h)return NULL;
  if(!expected||birth(h)!=expected){CloseHandle(h);SetLastError(ERROR_INVALID_DATA);return NULL;}return h;
}
static int name_arg(napi_env env,napi_value v,wchar_t out[128]) {
  char name[128];const char *prefix="Local\\KnowledgeCommand-";size_t length=strlen(prefix);
  if(!string(env,v,name,sizeof(name))||strlen(name)!=length+64||strncmp(name,prefix,length))return 0;
  for(size_t i=length;i<length+64;i++)if(!((name[i]>='0'&&name[i]<='9')||(name[i]>='a'&&name[i]<='f')))return 0;
  return MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,out,128)>0;
}
static Scope *get_scope(napi_env env,napi_value v) {
  unsigned long long id;if(!integer(env,v,32,&id))return NULL;
  Scope *s=&scopes[id-1];return s->open&&s->id==(unsigned)id?s:NULL;
}
static void stop_scope(Scope *s,LONG reason) {
  InterlockedOr(&s->reason,reason);
  if(InterlockedExchange(&s->stopped,1)==0){
    InterlockedExchange64(&s->stop_began,(LONG64)GetTickCount64());
    SetEvent(s->requested);
    if(!TerminateJobObject(s->job,1))InterlockedCompareExchange(&s->native_error,(LONG)GetLastError(),0);
  }
}
static int accounting(HANDLE h,JOBOBJECT_BASIC_ACCOUNTING_INFORMATION *a) {
  return QueryInformationJobObject(h,JobObjectBasicAccountingInformation,a,sizeof(*a),NULL)!=0;
}
static int limits_valid(HANDLE h) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;memset(&limits,0,sizeof(limits));
  return QueryInformationJobObject(h,JobObjectExtendedLimitInformation,&limits,sizeof(limits),NULL)&&
    (limits.BasicLimitInformation.LimitFlags&JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)&&
    !(limits.BasicLimitInformation.LimitFlags&(JOB_OBJECT_LIMIT_BREAKAWAY_OK|JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK));
}
static HANDLE create_private_job(const wchar_t *name) {
  /* OWNER RIGHTS suppresses the owner's implicit WRITE_DAC grant. The
   * creator gets the one original ALL_ACCESS handle from CreateJobObject;
   * every later open is restricted to observation and stop. There is no
   * inheritable handle and no exported assignment/limit mutation method. */
  PSECURITY_DESCRIPTOR descriptor=NULL;
  if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"D:P(A;;0x0012000c;;;OW)",SDDL_REVISION_1,&descriptor,NULL))return NULL;
  SECURITY_ATTRIBUTES attributes={sizeof(attributes),descriptor,FALSE};
  SetLastError(0);HANDLE job=CreateJobObjectW(&attributes,name);DWORD created=GetLastError();
  LocalFree(descriptor);
  if(!job||created==ERROR_ALREADY_EXISTS){if(job)CloseHandle(job);SetLastError(created);return NULL;}
  /* Verify actual access checks before any assignment or descriptor leaves
   * this process. A source claim cannot replace a kernel denied-open result. */
  DWORD denied[]={JOB_OBJECT_ASSIGN_PROCESS,JOB_OBJECT_SET_ATTRIBUTES,WRITE_DAC,WRITE_OWNER};
  for(size_t i=0;i<sizeof(denied)/sizeof(denied[0]);i++){
    SetLastError(0);HANDLE probe=OpenJobObjectW(denied[i],FALSE,name);DWORD error=GetLastError();
    if(probe||error!=ERROR_ACCESS_DENIED){if(probe)CloseHandle(probe);CloseHandle(job);SetLastError(ERROR_INVALID_ACCESS);return NULL;}
  }
  HANDLE observer=OpenJobObjectW(JOB_OBJECT_QUERY|JOB_OBJECT_TERMINATE,FALSE,name);
  if(!observer){DWORD error=GetLastError();CloseHandle(job);SetLastError(error);return NULL;}
  CloseHandle(observer);SetLastError(0);return job;
}
static DWORD WINAPI control_loop(void *argument) {
  Scope *s=(Scope*)argument;HANDLE event=CreateEventW(NULL,TRUE,FALSE,NULL);
  if(!event){stop_scope(s,STOP_UNKNOWN);return 1;}
  OVERLAPPED request;memset(&request,0,sizeof(request));request.hEvent=event;unsigned char value;DWORD count=0;
  BOOL ok=ReadFile(s->pipe,&value,1,&count,&request);
  if(!ok&&GetLastError()==ERROR_IO_PENDING){
    HANDLE waits[2]={s->shutdown,event};DWORD which=WaitForMultipleObjects(2,waits,FALSE,INFINITE);
    if(which==WAIT_OBJECT_0){CancelIoEx(s->pipe,&request);GetOverlappedResult(s->pipe,&request,&count,TRUE);CloseHandle(event);return 0;}
    ok=which==WAIT_OBJECT_0+1&&GetOverlappedResult(s->pipe,&request,&count,FALSE);
  }
  /* Any byte, EOF, malformed input or read failure irrevocably closes
   * admission. There is no resume command on the independent native pipe. */
  (void)ok;(void)count;stop_scope(s,STOP_CONTROL);CloseHandle(event);return 0;
}
static DWORD WINAPI watch_loop(void *argument) {
  Scope *s=(Scope*)argument;
  for(;;){
    if(signaled(s->shutdown))return 0;
    unsigned long long now=GetTickCount64();
    if(now<s->began||now-s->began>=s->lifetime)stop_scope(s,STOP_LIFETIME);
    if(signaled(s->parent))stop_scope(s,STOP_PARENT);
    HANDLE peer=(HANDLE)InterlockedCompareExchangePointer((PVOID volatile*)&s->peer,NULL,NULL);
    if(peer&&signaled(peer))stop_scope(s,STOP_PEER);
    if(signaled(s->root))stop_scope(s,STOP_ROOT);
    if(InterlockedCompareExchange(&s->stopped,0,0)){
      JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;memset(&a,0,sizeof(a));
      if(!accounting(s->job,&a))InterlockedCompareExchange(&s->native_error,(LONG)GetLastError(),0);
      else if(a.ActiveProcesses==0&&signaled(s->root))InterlockedExchange(&s->drained,1);
      else if(!TerminateJobObject(s->job,1))InterlockedCompareExchange(&s->native_error,(LONG)GetLastError(),0);
      unsigned long long stopped=(unsigned long long)InterlockedCompareExchange64(&s->stop_began,0,0);
      /* Bounded failure exit is not a cleanup receipt. The other holder may
       * have persisted one; if both fail before persistence, recovery remains
       * unconfirmed. This stops a holder even while its JS blocks in I/O. */
      unsigned long long cleanup_now=GetTickCount64();
      if(stopped&&(cleanup_now<stopped||cleanup_now-stopped>=s->cleanup_lifetime)){TerminateProcess(GetCurrentProcess(),125);return 1;}
    }
    HANDLE waits[2]={s->shutdown,s->requested};WaitForMultipleObjects(2,waits,FALSE,20);
    /* An auto-reset request event permits bounded periodic observations. */
  }
}
static void close_handles(Scope *s) {
  HANDLE values[]={s->control_thread,s->watch_thread,s->pipe,s->shutdown,s->requested,s->peer,s->parent,s->root,s->job};
  for(size_t i=0;i<sizeof(values)/sizeof(values[0]);i++)if(values[i])CloseHandle(values[i]);
  s->open=0;
}
static int arm(Scope *s) {
  HANDLE input=(HANDLE)_get_osfhandle(0);
  s->shutdown=CreateEventW(NULL,TRUE,FALSE,NULL);s->requested=CreateEventW(NULL,FALSE,FALSE,NULL);
  if(input==INVALID_HANDLE_VALUE||GetFileType(input)!=FILE_TYPE_PIPE||!s->shutdown||!s->requested||
    !DuplicateHandle(GetCurrentProcess(),input,GetCurrentProcess(),&s->pipe,0,FALSE,DUPLICATE_SAME_ACCESS))return 0;
  s->watch_thread=CreateThread(NULL,0,watch_loop,s,0,NULL);s->control_thread=CreateThread(NULL,0,control_loop,s,0,NULL);
  if(!s->watch_thread||!s->control_thread){stop_scope(s,STOP_UNKNOWN);return 0;}return 1;
}
static napi_value info(napi_env env,napi_callback_info ignored) {
  (void)ignored;napi_value obj;napi_create_object(env,&obj);
  text(env,obj,"schema_version","knowledge-command-windows-native.v1");text(env,obj,"source_sha256",KNOWLEDGE_COMMAND_JOB_SOURCE_SHA256);
  text(env,obj,"platform","win32");text(env,obj,"architecture",JOB_ARCH);number(env,obj,"napi_version",8);
  text(env,obj,"assignment","exact-root-once-no-breakaway.v1");text(env,obj,"watchdog","native-pipe-process-handles.v1");return obj;
}
static napi_value current_identity(napi_env env,napi_callback_info ignored) {
  (void)ignored;unsigned long long created=birth(GetCurrentProcess());if(!created)return fail(env,"windows_birth_unavailable",GetLastError());
  return identity(env,GetCurrentProcessId(),created);
}
static napi_value process_identity(napi_env env,napi_callback_info cb) {
  napi_value args[1];size_t count=1;unsigned long long pid;napi_get_cb_info(env,cb,&count,args,NULL,NULL);
  if(count!=1||!integer(env,args[0],0xffffffffu,&pid))return fail(env,"windows_process_invalid",0);
  HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,(DWORD)pid);
  if(!h)return fail(env,"windows_process_unconfirmed",GetLastError());
  unsigned long long created=birth(h);int exited=signaled(h);CloseHandle(h);
  if(!created)return fail(env,"windows_birth_unavailable",GetLastError());
  napi_value value=identity(env,(DWORD)pid,created);boolean(env,value,"exited",exited);return value;
}
static napi_value create_scope(napi_env env,napi_callback_info cb) {
  napi_value args[7];size_t count=7;napi_get_cb_info(env,cb,&count,args,NULL,NULL);
  wchar_t name[128];unsigned long long lifetime,cleanup;DWORD root_pid,parent_pid;unsigned long long root_birth,parent_birth;bool durable=false;
  if(count!=7||!name_arg(env,args[0],name)||!identity_arg(env,args[1],&root_pid,&root_birth)||
    !identity_arg(env,args[2],&parent_pid,&parent_birth)||!integer(env,args[3],2147483647,&lifetime)||
    napi_get_value_bool(env,args[4],&durable)!=napi_ok||!integer(env,args[6],2147483647,&cleanup))return fail(env,"windows_job_arguments_invalid",0);
  /* The sixth argument is the fixed protocol version, never options/callbacks. */
  char protocol[64];if(!string(env,args[5],protocol,sizeof(protocol))||strcmp(protocol,"exact-root-once-no-breakaway.v1")||
    root_pid==parent_pid||root_pid==GetCurrentProcessId()||parent_pid==GetCurrentProcessId())return fail(env,"windows_job_arguments_invalid",0);
  LONG id=InterlockedIncrement(&next_id);if(id<1||id>32)return fail(env,"windows_job_table_full",0);
  Scope *s=&scopes[id-1];memset(s,0,sizeof(*s));s->id=(unsigned)id;s->creator=1;s->requires_durable=durable?1:0;
  s->root_pid=root_pid;s->root_birth=root_birth;s->parent_pid=parent_pid;s->parent_birth=parent_birth;s->began=GetTickCount64();s->lifetime=lifetime;s->cleanup_lifetime=cleanup;
  s->root=exact_process(root_pid,root_birth,0);s->parent=exact_process(parent_pid,parent_birth,0);
  if(!s->root||!s->parent||signaled(s->root)||signaled(s->parent)){DWORD code=GetLastError();close_handles(s);return fail(env,"windows_job_birth_changed",code);}
  s->job=create_private_job(name);DWORD created=GetLastError();
  if(!s->job){close_handles(s);return fail(env,"windows_job_access_unconfirmed",created);}
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;memset(&limits,0,sizeof(limits));limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if(!SetInformationJobObject(s->job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))||!limits_valid(s->job)){
    DWORD code=GetLastError();close_handles(s);return fail(env,"windows_job_limits_unconfirmed",code);}
  /* Assignment exists only here, once, before publishing any descriptor. No
   * exported assign API or opened handle can admit another process root. */
  HANDLE assign=exact_process(root_pid,root_birth,PROCESS_SET_QUOTA|PROCESS_TERMINATE);
  if(!assign||!AssignProcessToJobObject(s->job,assign)){DWORD code=GetLastError();if(assign)CloseHandle(assign);close_handles(s);return fail(env,"windows_job_assignment_failed",code);}
  CloseHandle(assign);s->open=1;
  if(!arm(s))return fail(env,"windows_job_watchdog_unconfirmed",GetLastError());
  napi_value out;napi_create_object(env,&out);number(env,out,"id",s->id);napi_set_named_property(env,out,"keeper",identity(env,GetCurrentProcessId(),birth(GetCurrentProcess())));
  napi_set_named_property(env,out,"root",identity(env,root_pid,root_birth));napi_set_named_property(env,out,"controller",identity(env,parent_pid,parent_birth));return out;
}
static napi_value open_scope(napi_env env,napi_callback_info cb) {
  napi_value args[6];size_t count=6;napi_get_cb_info(env,cb,&count,args,NULL,NULL);wchar_t name[128];
  DWORD root_pid,parent_pid,peer_pid;unsigned long long root_birth,parent_birth,peer_birth,lifetime,cleanup;
  if(count!=6||!name_arg(env,args[0],name)||!identity_arg(env,args[1],&root_pid,&root_birth)||
    !identity_arg(env,args[2],&parent_pid,&parent_birth)||!identity_arg(env,args[3],&peer_pid,&peer_birth)||
    !integer(env,args[4],2147483647,&lifetime)||!integer(env,args[5],2147483647,&cleanup)||peer_pid==root_pid||peer_pid==parent_pid||root_pid==parent_pid||
    peer_pid==GetCurrentProcessId()||parent_pid==GetCurrentProcessId())return fail(env,"windows_custodian_arguments_invalid",0);
  LONG id=InterlockedIncrement(&next_id);if(id<1||id>32)return fail(env,"windows_job_table_full",0);
  Scope *s=&scopes[id-1];memset(s,0,sizeof(*s));s->id=(unsigned)id;s->requires_durable=1;
  s->root_pid=root_pid;s->root_birth=root_birth;s->parent_pid=parent_pid;s->parent_birth=parent_birth;s->peer_pid=peer_pid;s->peer_birth=peer_birth;
  s->began=GetTickCount64();s->lifetime=lifetime;s->cleanup_lifetime=cleanup;
  s->root=exact_process(root_pid,root_birth,0);s->parent=exact_process(parent_pid,parent_birth,0);s->peer=exact_process(peer_pid,peer_birth,PROCESS_TERMINATE);
  s->job=OpenJobObjectW(JOB_OBJECT_QUERY|JOB_OBJECT_TERMINATE,FALSE,name);
  if(!s->root||!s->parent||!s->peer||!s->job||!limits_valid(s->job)){
    DWORD code=GetLastError();close_handles(s);return fail(env,"windows_custodian_binding_unconfirmed",code);}
  BOOL member=FALSE;if(!IsProcessInJob(s->root,s->job,&member)||!member||signaled(s->root)){
    close_handles(s);return fail(env,"windows_custodian_root_unconfirmed",0);}
  s->open=1;if(!arm(s))return fail(env,"windows_job_watchdog_unconfirmed",GetLastError());
  napi_value out;napi_create_object(env,&out);number(env,out,"id",s->id);napi_set_named_property(env,out,"holder",identity(env,GetCurrentProcessId(),birth(GetCurrentProcess())));return out;
}
static napi_value attach_peer(napi_env env,napi_callback_info cb) {
  napi_value args[2];size_t count=2;napi_get_cb_info(env,cb,&count,args,NULL,NULL);DWORD pid;unsigned long long created;
  Scope *s=count==2?get_scope(env,args[0]):NULL;
  if(!s||!s->creator||!identity_arg(env,args[1],&pid,&created)||s->peer||pid==s->root_pid||pid==s->parent_pid||pid==GetCurrentProcessId())return fail(env,"windows_peer_invalid",0);
  HANDLE h=exact_process(pid,created,PROCESS_TERMINATE);if(!h||signaled(h)){if(h)CloseHandle(h);return fail(env,"windows_peer_unconfirmed",GetLastError());}
  s->peer_pid=pid;s->peer_birth=created;InterlockedExchangePointer((PVOID volatile*)&s->peer,h);napi_value out;napi_get_boolean(env,true,&out);return out;
}
static napi_value poll_scope(napi_env env,napi_callback_info cb) {
  napi_value args[1];size_t count=1;napi_get_cb_info(env,cb,&count,args,NULL,NULL);Scope *s=count==1?get_scope(env,args[0]):NULL;
  if(!s)return fail(env,"windows_scope_invalid",0);JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;memset(&a,0,sizeof(a));int ok=accounting(s->job,&a);
  napi_value out;napi_create_object(env,&out);boolean(env,out,"stop_latched",s->stopped);number(env,out,"stop_reason",s->reason);
  boolean(env,out,"root_exited",signaled(s->root));boolean(env,out,"parent_exited",signaled(s->parent));boolean(env,out,"peer_exited",s->peer&&signaled(s->peer));
  boolean(env,out,"kernel_query_ok",ok);if(ok)number(env,out,"active_processes",a.ActiveProcesses);else number(env,out,"query_error",GetLastError());
  boolean(env,out,"drained",s->stopped&&s->drained&&ok&&a.ActiveProcesses==0&&signaled(s->root));
  boolean(env,out,"receipt_durable",s->durable);number(env,out,"native_error",s->native_error);return out;
}
static napi_value request_stop(napi_env env,napi_callback_info cb) {
  napi_value args[1];size_t count=1;napi_get_cb_info(env,cb,&count,args,NULL,NULL);Scope *s=count==1?get_scope(env,args[0]):NULL;
  if(!s)return fail(env,"windows_scope_invalid",0);stop_scope(s,STOP_CONTROL);napi_value out;napi_get_boolean(env,true,&out);return out;
}
static napi_value mark_durable(napi_env env,napi_callback_info cb) {
  napi_value args[1];size_t count=1;napi_get_cb_info(env,cb,&count,args,NULL,NULL);Scope *s=count==1?get_scope(env,args[0]):NULL;
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;
  if(!s||!s->stopped||!s->drained||!accounting(s->job,&a)||a.ActiveProcesses||!signaled(s->root))return fail(env,"windows_scope_not_drained",0);
  InterlockedExchange(&s->durable,1);napi_value out;napi_get_boolean(env,true,&out);return out;
}
static napi_value retire_peer(napi_env env,napi_callback_info cb) {
  napi_value args[1];size_t count=1;napi_get_cb_info(env,cb,&count,args,NULL,NULL);Scope *s=count==1?get_scope(env,args[0]):NULL;
  if(!s||!s->durable||!s->drained||!s->peer)return fail(env,"windows_peer_retirement_unconfirmed",0);
  int ok=signaled(s->peer)||TerminateProcess(s->peer,125);napi_value out;napi_get_boolean(env,ok!=0,&out);return out;
}
static napi_value close_scope(napi_env env,napi_callback_info cb) {
  napi_value args[1];size_t count=1;napi_get_cb_info(env,cb,&count,args,NULL,NULL);Scope *s=count==1?get_scope(env,args[0]):NULL;
  if(!s)return fail(env,"windows_scope_invalid",0);
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;int closed=0;
  if(s->stopped&&s->drained&&(!s->requires_durable||s->durable)&&accounting(s->job,&a)&&a.ActiveProcesses==0&&signaled(s->root)){
    SetEvent(s->shutdown);if(s->pipe)CancelIoEx(s->pipe,NULL);if(s->control_thread)CancelSynchronousIo(s->control_thread);
    if((!s->watch_thread||signaled(s->watch_thread))&&(!s->control_thread||signaled(s->control_thread))){close_handles(s);closed=1;}
  }
  napi_value out;napi_get_boolean(env,closed!=0,&out);return out;
}
static napi_value observe_scope(napi_env env,napi_callback_info cb) {
  napi_value args[2];size_t count=2;napi_get_cb_info(env,cb,&count,args,NULL,NULL);wchar_t name[128];DWORD pid;unsigned long long expected;
  if(count!=2||!name_arg(env,args[0],name)||!identity_arg(env,args[1],&pid,&expected))return fail(env,"windows_observer_invalid",0);
  napi_value out;napi_create_object(env,&out);HANDLE job=OpenJobObjectW(JOB_OBJECT_QUERY,FALSE,name);
  if(!job){DWORD code=GetLastError();text(env,out,"status",code==ERROR_FILE_NOT_FOUND?"missing":"unconfirmed");number(env,out,"native_error",code);return out;}
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;memset(&a,0,sizeof(a));
  if(!limits_valid(job)||!accounting(job,&a)){text(env,out,"status","unconfirmed");CloseHandle(job);return out;}
  HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,pid);int dead=0;const char *basis="unconfirmed";
  if(process){unsigned long long actual=birth(process);BOOL member=FALSE;
    if(actual&&actual!=expected){dead=1;basis="exact_birth_replaced";}
    else if(actual==expected&&signaled(process)){dead=1;basis="exact_handle_signaled";}
    else if(actual==expected&&IsProcessInJob(process,job,&member)&&member)basis="exact_member_active";
    CloseHandle(process);
  } else if(GetLastError()==ERROR_INVALID_PARAMETER){dead=1;basis="exact_pid_absent";}
  number(env,out,"active_processes",a.ActiveProcesses);boolean(env,out,"root_exited",dead);text(env,out,"root_basis",basis);
  text(env,out,"status",a.ActiveProcesses==0&&dead?"completed":!strcmp(basis,"exact_member_active")||a.ActiveProcesses>0?"active":"unconfirmed");
  CloseHandle(job);return out;
}
static napi_value member_of(napi_env env,napi_callback_info cb) {
  napi_value args[2];size_t count=2;napi_get_cb_info(env,cb,&count,args,NULL,NULL);wchar_t name[128];DWORD pid;unsigned long long expected;
  if(count!=2||!name_arg(env,args[0],name)||!identity_arg(env,args[1],&pid,&expected))return fail(env,"windows_membership_invalid",0);
  HANDLE job=OpenJobObjectW(JOB_OBJECT_QUERY,FALSE,name),process=exact_process(pid,expected,0);BOOL member=FALSE;
  int known=job&&process&&!signaled(process)&&limits_valid(job)&&IsProcessInJob(process,job,&member);
  if(job)CloseHandle(job);if(process)CloseHandle(process);
  if(!known)return fail(env,"windows_membership_unconfirmed",GetLastError());
  napi_value out;napi_get_boolean(env,member!=0,&out);return out;
}
typedef struct { HANDLE parent; unsigned long long began,lifetime; } ReadGuard;
static volatile LONG readonly_guard_armed;
static DWORD WINAPI readonly_guard_loop(void *argument) {
  ReadGuard *guard=(ReadGuard*)argument;
  for(;;){
    DWORD observed=WaitForSingleObject(guard->parent,20);unsigned long long current=GetTickCount64();
    if(observed!=WAIT_TIMEOUT||current<guard->began||current-guard->began>=guard->lifetime){
      TerminateProcess(GetCurrentProcess(),124);return 1;
    }
  }
}
static napi_value arm_readonly_guard(napi_env env,napi_callback_info cb) {
  napi_value args[2];size_t count=2;napi_get_cb_info(env,cb,&count,args,NULL,NULL);DWORD pid;unsigned long long created,lifetime;
  if(count!=2||!identity_arg(env,args[0],&pid,&created)||pid==GetCurrentProcessId()||!integer(env,args[1],600000,&lifetime)||
      InterlockedCompareExchange(&readonly_guard_armed,1,0))return fail(env,"windows_readonly_guard_invalid",0);
  ReadGuard *guard=(ReadGuard*)calloc(1,sizeof(*guard));if(!guard)return fail(env,"windows_readonly_guard_unconfirmed",ERROR_NOT_ENOUGH_MEMORY);
  guard->parent=exact_process(pid,created,0);guard->began=GetTickCount64();guard->lifetime=lifetime;
  if(!guard->parent||signaled(guard->parent)){if(guard->parent)CloseHandle(guard->parent);free(guard);return fail(env,"windows_readonly_guard_unconfirmed",0);}
  HANDLE thread=CreateThread(NULL,0,readonly_guard_loop,guard,0,NULL);
  if(!thread){DWORD error=GetLastError();CloseHandle(guard->parent);free(guard);return fail(env,"windows_readonly_guard_unconfirmed",error);}
  CloseHandle(thread);napi_value out;napi_get_boolean(env,true,&out);return out;
}
static napi_value host_binding(napi_env env,napi_callback_info ignored) {
  (void)ignored;HKEY key=NULL;WCHAR guid[512];DWORD length=sizeof(guid),type=0;
  LONG status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Cryptography",0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key);
  if(status!=ERROR_SUCCESS)return fail(env,"windows_host_unconfirmed",(DWORD)status);
  status=RegQueryValueExW(key,L"MachineGuid",NULL,&type,(BYTE*)guid,&length);RegCloseKey(key);
  if(status!=ERROR_SUCCESS||type!=REG_SZ||length<sizeof(WCHAR)||length>sizeof(guid)||guid[length/sizeof(WCHAR)-1]!=0)return fail(env,"windows_host_unconfirmed",(DWORD)status);
  HANDLE token=NULL;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return fail(env,"windows_user_unconfirmed",GetLastError());
  DWORD needed=0;GetTokenInformation(token,TokenUser,NULL,0,&needed);
  if(!needed||needed>65536){CloseHandle(token);return fail(env,"windows_user_unconfirmed",0);}
  TOKEN_USER *user=(TOKEN_USER*)malloc(needed);LPWSTR sid=NULL;int ok=user&&GetTokenInformation(token,TokenUser,user,needed,&needed)&&ConvertSidToStringSidW(user->User.Sid,&sid);CloseHandle(token);
  if(!ok){if(user)free(user);return fail(env,"windows_user_unconfirmed",GetLastError());}
  WCHAR computer[256];DWORD chars=256,session=0;
  if(!GetComputerNameW(computer,&chars)||!ProcessIdToSessionId(GetCurrentProcessId(),&session)){LocalFree(sid);free(user);return fail(env,"windows_host_unconfirmed",GetLastError());}
  napi_value out,value;napi_create_object(env,&out);
  napi_create_string_utf16(env,(const char16_t*)guid,NAPI_AUTO_LENGTH,&value);napi_set_named_property(env,out,"machine_guid",value);
  napi_create_string_utf16(env,(const char16_t*)computer,NAPI_AUTO_LENGTH,&value);napi_set_named_property(env,out,"computer_name",value);
  napi_create_string_utf16(env,(const char16_t*)sid,NAPI_AUTO_LENGTH,&value);napi_set_named_property(env,out,"user_sid",value);number(env,out,"session_id",session);
  LocalFree(sid);free(user);return out;
}
static napi_value initialize(napi_env env,napi_value exports) {
  napi_property_descriptor properties[]={
    {"info",0,info,0,0,0,napi_default,0},{"currentIdentity",0,current_identity,0,0,0,napi_default,0},
    {"processIdentity",0,process_identity,0,0,0,napi_default,0},{"hostBinding",0,host_binding,0,0,0,napi_default,0},
    {"create",0,create_scope,0,0,0,napi_default,0},{"open",0,open_scope,0,0,0,napi_default,0},{"attachPeer",0,attach_peer,0,0,0,napi_default,0},
    {"poll",0,poll_scope,0,0,0,napi_default,0},{"stop",0,request_stop,0,0,0,napi_default,0},
    {"markDurable",0,mark_durable,0,0,0,napi_default,0},{"retirePeer",0,retire_peer,0,0,0,napi_default,0},
    {"close",0,close_scope,0,0,0,napi_default,0},{"observe",0,observe_scope,0,0,0,napi_default,0},
    {"memberOf",0,member_of,0,0,0,napi_default,0},{"armReadonlyGuard",0,arm_readonly_guard,0,0,0,napi_default,0}};
  napi_define_properties(env,exports,sizeof(properties)/sizeof(properties[0]),properties);return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME,initialize)
