/* Actual Windows-only diagnostic. No simulated Win32 return values.
 * Compare the Win32 wrapper and the direct NT service with the same pinned
 * directory HANDLE and relative FILE_RENAME_INFO layout. Every mutation is
 * inside the fresh, controller-owned argv[1] directory. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef NTSTATUS (NTAPI *set_information_fn)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef ULONG (WINAPI *dos_error_fn)(NTSTATUS);
_Static_assert(sizeof(void *) == 8 && offsetof(FILE_RENAME_INFO, RootDirectory) == 8 &&
  offsetof(FILE_RENAME_INFO, FileNameLength) == 16 && offsetof(FILE_RENAME_INFO, FileName) == 20,
  "Unexpected FILE_RENAME_INFO ABI");

static int join(wchar_t *out, const wchar_t *parent, const wchar_t *leaf) {
  return _snwprintf_s(out, 32768, _TRUNCATE, L"%ls\\%ls", parent, leaf) >= 0;
}
static int same(const BY_HANDLE_FILE_INFORMATION *a, const BY_HANDLE_FILE_INFORMATION *b) {
  return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber &&
    a->nFileIndexHigh == b->nFileIndexHigh && a->nFileIndexLow == b->nFileIndexLow;
}
static HANDLE directory(const wchar_t *path, int deleting) {
  return CreateFileW(path, FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE | (deleting ? DELETE : 0),
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
}
static int path_identity(const wchar_t *path, BY_HANDLE_FILE_INFORMATION *info) {
  HANDLE h = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  int ok = GetFileInformationByHandle(h, info); CloseHandle(h); return ok;
}
static int create_file(const wchar_t *path) {
  HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  DWORD written = 0; int ok = WriteFile(h, "complete\n", 9, &written, NULL) && written == 9 && FlushFileBuffers(h);
  CloseHandle(h); return ok;
}
static int one(const wchar_t *root, const wchar_t *label, const char *name,
    int use_nt, int old_buffer_length, int open_owner, int collision) {
  wchar_t base[32768], source[32768], target_parent[32768], target[32768], owner_path[32768], sentinel[32768];
  HANDLE source_handle = INVALID_HANDLE_VALUE, parent_handle = INVALID_HANDLE_VALUE, owner = INVALID_HANDLE_VALUE, event = NULL;
  FILE_RENAME_INFO *info = NULL;
  DWORD error = 0; NTSTATUS ntstatus = 0; int success = 0, valid = 0, setup_ok = 0;
  int directory_same = 0, owner_same = 0, source_retained = 0, collision_preserved = 0;
  BY_HANDLE_FILE_INFORMATION original, owner_original, target_original, after;
  if (!join(base,root,label) || !CreateDirectoryW(base,NULL) ||
      !join(source,base,L"source") || !CreateDirectoryW(source,NULL) ||
      !join(target_parent,base,L"destination") || !CreateDirectoryW(target_parent,NULL) ||
      !join(target,target_parent,L"target") || !join(owner_path,source,L"owner.json") || !create_file(owner_path)) goto done;
  if (collision) {
    if (collision == 3) { if (!create_file(target)) goto done; }
    else {
      if (!CreateDirectoryW(target,NULL)) goto done;
      if (collision == 2 && (!join(sentinel,target,L"foreign") || !create_file(sentinel))) goto done;
    }
    if (!path_identity(target,&target_original)) goto done;
  }
  source_handle=directory(source,1); parent_handle=directory(target_parent,0);
  if (source_handle==INVALID_HANDLE_VALUE || parent_handle==INVALID_HANDLE_VALUE ||
      !GetFileInformationByHandle(source_handle,&original)) goto done;
  if (open_owner) {
    owner=CreateFileW(owner_path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
      NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    OVERLAPPED range; ZeroMemory(&range,sizeof(range)); range.Offset=1048576;
    if(owner==INVALID_HANDLE_VALUE || !GetFileInformationByHandle(owner,&owner_original))goto done;
    if(open_owner==1) {
      if(!LockFileEx(owner,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,0,1,0,&range))goto done;
    } else {
      wchar_t event_name[160];
      _snwprintf_s(event_name,160,_TRUNCATE,L"Global\\KnowledgeOwnerLease-v1-%08lX-%016llX-%016llX",
        (unsigned long)owner_original.dwVolumeSerialNumber,
        ((unsigned long long)owner_original.nFileIndexHigh<<32)|owner_original.nFileIndexLow,
        ((unsigned long long)original.nFileIndexHigh<<32)|original.nFileIndexLow);
      CloseHandle(owner);owner=INVALID_HANDLE_VALUE;
      SetLastError(ERROR_SUCCESS);event=CreateEventExW(NULL,event_name,CREATE_EVENT_MANUAL_RESET,SYNCHRONIZE);
      DWORD event_error=GetLastError();if(!event || event_error!=ERROR_SUCCESS)goto done;
    }
  }
  const wchar_t *leaf=L"target"; size_t length=wcslen(leaf)*sizeof(wchar_t);
  size_t allocated=sizeof(FILE_RENAME_INFO)+length;
  DWORD supplied=(DWORD)(old_buffer_length ? offsetof(FILE_RENAME_INFO,FileName)+length : allocated);
  info=(FILE_RENAME_INFO *)calloc(1,allocated); if(!info)goto done;
  info->ReplaceIfExists=FALSE;info->RootDirectory=parent_handle;info->FileNameLength=(DWORD)length;
  memcpy(info->FileName,leaf,length);setup_ok=1;
  SetLastError(ERROR_SUCCESS);
  if(use_nt) {
    HMODULE module=GetModuleHandleW(L"ntdll.dll");
    set_information_fn set_information=(set_information_fn)GetProcAddress(module,"NtSetInformationFile");
    dos_error_fn dos_error=(dos_error_fn)GetProcAddress(module,"RtlNtStatusToDosError");
    if(!set_information || !dos_error) {error=ERROR_NOT_SUPPORTED;goto done;}
    IO_STATUS_BLOCK io;ZeroMemory(&io,sizeof(io));
    ntstatus=set_information(source_handle,&io,info,supplied,(FILE_INFORMATION_CLASS)10);
    success=ntstatus==0 && io.Status==0;
    error=success?0:dos_error(ntstatus!=0?ntstatus:io.Status);
  } else {
    success=SetFileInformationByHandle(source_handle,FileRenameInfo,info,supplied);
    error=success?0:GetLastError();
  }
  source_retained=path_identity(source,&after) && same(&original,&after);
  directory_same=path_identity(target,&after) && same(&original,&after);
  if(collision)collision_preserved=path_identity(target,&after) && same(&target_original,&after);
  if(open_owner && success) {
    if(!join(owner_path,target,L"owner.json"))goto done;
    owner_same=path_identity(owner_path,&after) && same(&owner_original,&after);
  } else owner_same=!open_owner;
  if(use_nt && open_owner==1)valid=!success && error==ERROR_ACCESS_DENIED && source_retained;
  else if(use_nt)valid=collision ? !success && source_retained && collision_preserved &&
    (error==ERROR_ALREADY_EXISTS || error==ERROR_FILE_EXISTS) : success && directory_same && !source_retained && owner_same;
  else valid=success ? directory_same && !source_retained : source_retained && GetFileAttributesW(target)==INVALID_FILE_ATTRIBUTES;
done:
  if(!setup_ok && !error)error=GetLastError();
  printf("{\"case\":\"%s\",\"api\":\"%s\",\"setup_complete\":%s,\"published\":%s,\"native_error\":%lu,\"ntstatus\":%ld,\"open_owner_file_lease\":%s,\"kernel_event_lease\":%s,\"old_buffer_length\":%s,\"directory_same\":%s,\"owner_same\":%s,\"source_retained\":%s,\"collision_preserved\":%s,\"contract_satisfied\":%s}\n",
    name,use_nt?"NtSetInformationFile":"SetFileInformationByHandle",setup_ok?"true":"false",success?"true":"false",(unsigned long)error,(long)ntstatus,
    open_owner==1?"true":"false",open_owner==2?"true":"false",old_buffer_length?"true":"false",directory_same?"true":"false",owner_same?"true":"false",
    source_retained?"true":"false",collision_preserved?"true":"false",valid?"true":"false");
  if(owner!=INVALID_HANDLE_VALUE)CloseHandle(owner);
  if(event)CloseHandle(event);
  if(parent_handle!=INVALID_HANDLE_VALUE)CloseHandle(parent_handle);
  if(source_handle!=INVALID_HANDLE_VALUE)CloseHandle(source_handle);
  free(info);return valid;
}
static int event_lifetime(const wchar_t *root) {
  BY_HANDLE_FILE_INFORMATION identity;if(!path_identity(root,&identity))return 0;
  wchar_t name[160];_snwprintf_s(name,160,_TRUNCATE,L"Global\\KnowledgeOwnerLeaseProbe-%08lX-%016llX",
    (unsigned long)identity.dwVolumeSerialNumber,((unsigned long long)identity.nFileIndexHigh<<32)|identity.nFileIndexLow);
  HANDLE holder=NULL,observer=NULL,probe=NULL,foreign=NULL;int ok=0;
  int held_busy=0,duplicate_busy=0,fully_closed_new=0,type_collision_denied=0,acl_denied=0;
  SetLastError(ERROR_SUCCESS);holder=CreateEventExW(NULL,name,CREATE_EVENT_MANUAL_RESET,SYNCHRONIZE);
  DWORD e=GetLastError();if(!holder || e!=ERROR_SUCCESS)goto done;
  if(!DuplicateHandle(GetCurrentProcess(),holder,GetCurrentProcess(),&observer,0,FALSE,DUPLICATE_SAME_ACCESS))goto done;
  SetLastError(ERROR_SUCCESS);probe=CreateEventExW(NULL,name,0,SYNCHRONIZE);e=GetLastError();
  held_busy=probe && e==ERROR_ALREADY_EXISTS;if(probe){CloseHandle(probe);probe=NULL;}
  CloseHandle(holder);holder=NULL;
  SetLastError(ERROR_SUCCESS);probe=CreateEventExW(NULL,name,0,SYNCHRONIZE);e=GetLastError();
  duplicate_busy=probe && e==ERROR_ALREADY_EXISTS;if(probe){CloseHandle(probe);probe=NULL;}
  CloseHandle(observer);observer=NULL;
  SetLastError(ERROR_SUCCESS);probe=CreateEventExW(NULL,name,0,SYNCHRONIZE);e=GetLastError();
  fully_closed_new=probe && e==ERROR_SUCCESS;if(probe){CloseHandle(probe);probe=NULL;}
  SetLastError(ERROR_SUCCESS);foreign=CreateMutexW(NULL,FALSE,name);e=GetLastError();if(!foreign || e!=ERROR_SUCCESS)goto done;
  SetLastError(ERROR_SUCCESS);probe=CreateEventExW(NULL,name,0,SYNCHRONIZE);e=GetLastError();
  type_collision_denied=!probe && e==ERROR_INVALID_HANDLE;if(probe){CloseHandle(probe);probe=NULL;}
  CloseHandle(foreign);foreign=NULL;
  SECURITY_DESCRIPTOR sd;ACL deny_all;
  if(!InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION) || !InitializeAcl(&deny_all,sizeof(deny_all),ACL_REVISION) ||
    !SetSecurityDescriptorDacl(&sd,TRUE,&deny_all,FALSE))goto done;
  SECURITY_ATTRIBUTES attributes={sizeof(attributes),&sd,FALSE};
  SetLastError(ERROR_SUCCESS);holder=CreateEventExW(&attributes,name,0,SYNCHRONIZE);e=GetLastError();if(!holder || e!=ERROR_SUCCESS)goto done;
  SetLastError(ERROR_SUCCESS);probe=CreateEventExW(NULL,name,0,SYNCHRONIZE);e=GetLastError();
  acl_denied=!probe && e==ERROR_ACCESS_DENIED;
  ok=held_busy && duplicate_busy && fully_closed_new && type_collision_denied && acl_denied;
done:
  printf("{\"case\":\"global-event-lifetime-and-negative-access\",\"held_busy\":%s,\"duplicate_handle_delays_recovery\":%s,\"last_handle_close_allows_new_object\":%s,\"wrong_object_type_not_available\":%s,\"access_denied_not_available\":%s,\"contract_satisfied\":%s}\n",
    held_busy?"true":"false",duplicate_busy?"true":"false",fully_closed_new?"true":"false",type_collision_denied?"true":"false",acl_denied?"true":"false",ok?"true":"false");
  if(probe)CloseHandle(probe);if(holder)CloseHandle(holder);if(observer)CloseHandle(observer);if(foreign)CloseHandle(foreign);
  return ok;
}
int wmain(int argc,wchar_t **argv) {
  if(argc!=2 || !CreateDirectoryW(argv[1],NULL) || !SetCurrentDirectoryW(argv[1]))return 2;
  int ok=1;
  ok&=one(argv[1],L"wrapper-old-length","win32-relative-original-buffer-length",0,1,0,0);
  ok&=one(argv[1],L"wrapper-complete-buffer","win32-relative-complete-buffer",0,0,0,0);
  ok&=one(argv[1],L"native-absent","nt-relative-absent",1,0,0,0);
  ok&=one(argv[1],L"native-owner-lease","nt-relative-open-owner-file-is-unsupported",1,0,1,0);
  ok&=one(argv[1],L"native-event-lease","nt-relative-event-lease",1,0,2,0);
  ok&=one(argv[1],L"native-empty-collision","nt-relative-empty-directory-collision",1,0,2,1);
  ok&=one(argv[1],L"native-nonempty-collision","nt-relative-nonempty-directory-collision",1,0,2,2);
  ok&=one(argv[1],L"native-file-collision","nt-relative-file-collision",1,0,2,3);
  ok&=event_lifetime(argv[1]);
  return ok?0:1;
}
