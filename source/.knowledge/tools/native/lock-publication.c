/*
 * In-process, N-API 8, exclusive publication of a prepared lock directory.
 * There is deliberately no ordinary-rename or copy/delete fallback.
 * Callers prepare and validate immutable owner/scope files before calling.
 */
#define _GNU_SOURCE 1
#define NAPI_VERSION 8
#include <node_api.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifndef KNOWLEDGE_LOCK_SOURCE_SHA256
#error "Build must bind the exact source SHA256"
#endif

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <linux/fs.h>
#elif defined(__APPLE__)
#include <sys/mount.h>
#include <sys/acl.h>
#include <CommonCrypto/CommonDigest.h>
#else
#error "Unsupported platform: no qualified exclusive directory publication"
#endif
#endif

#if defined(_WIN32)
#define LOCK_PLATFORM "win32"
#define OWNER_LEASE_PROTOCOL "windows-owner-event.v1"
#elif defined(__APPLE__)
#define LOCK_PLATFORM "darwin"
#define OWNER_LEASE_PROTOCOL "owner-inode-lease.v1"
#else
#define LOCK_PLATFORM "linux"
#define OWNER_LEASE_PROTOCOL "owner-inode-lease.v1"
#endif
#if defined(__x86_64__) || defined(_M_X64)
#define LOCK_ARCH "x64"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define LOCK_ARCH "arm64"
#else
#error "Unsupported architecture"
#endif

static napi_value text(napi_env env, const char *value) {
  napi_value result; napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &result); return result;
}
static void field(napi_env env, napi_value object, const char *key, const char *value) {
  napi_set_named_property(env, object, key, text(env, value));
}
static napi_value fail(napi_env env, const char *code, const char *message, unsigned long native_error) {
  napi_value error, number; napi_create_error(env, text(env, code), text(env, message), &error);
  napi_create_double(env, (double)native_error, &number); napi_set_named_property(env, error, "native_error", number);
  napi_throw(env, error); return NULL;
}
static char *string_argument(napi_env env, napi_value value, size_t maximum) {
  napi_valuetype type; size_t size = 0, used = 0;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_string ||
      napi_get_value_string_utf8(env, value, NULL, 0, &size) != napi_ok || !size || size > maximum) return NULL;
  char *result = (char *)malloc(size + 1); if (!result) return NULL;
  if (napi_get_value_string_utf8(env, value, result, size + 1, &used) != napi_ok || used != size || strlen(result) != size) {
    free(result); return NULL;
  }
  return result;
}
static int basename_valid(const char *value, int stage) {
  size_t size = strlen(value); if (!size || size > 240 || !strcmp(value, ".") || !strcmp(value, "..")) return 0;
  if (stage && strncmp(value, "publish-", 8)) return 0;
  for (size_t i = 0; i < size; i++) {
    unsigned char c = (unsigned char)value[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return 0;
  }
  return size > 5 && !strcmp(value + size - 5, ".lock");
}
static napi_value info(napi_env env, napi_callback_info ignored) {
  (void)ignored; napi_value value; napi_create_object(env, &value);
  field(env, value, "schema_version", "knowledge-lock-publication-native.v1");
  field(env, value, "source_sha256", KNOWLEDGE_LOCK_SOURCE_SHA256);
  field(env, value, "platform", LOCK_PLATFORM); field(env, value, "architecture", LOCK_ARCH);
  field(env, value, "lease_protocol", OWNER_LEASE_PROTOCOL);
  napi_value version; napi_create_uint32(env, 8, &version); napi_set_named_property(env, value, "napi_version", version);
  return value;
}

static double monotonic_ms(void) {
#if defined(_WIN32)
  LARGE_INTEGER value, frequency;
  if (!QueryPerformanceCounter(&value) || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) return -1;
  return ((double)value.QuadPart / (double)frequency.QuadPart) * 1000.0;
#else
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
  return (double)now.tv_sec * 1000.0 + (double)now.tv_nsec / 1000000.0;
#endif
}

static int budget_expired(double start, double budget) {
  double now = monotonic_ms();
  return start < 0 || now < start || now - start >= budget;
}

#if !defined(_WIN32)
typedef struct { int root, locks, version, release, stage; struct stat r, v, p, s; } anchors;
typedef struct { int file; struct stat owner, directory; unsigned char raw[4097]; size_t used; } owner_lease;
static void initialize_lease(owner_lease *lease) { memset(lease, 0, sizeof(*lease)); lease->file = -1; }
static void close_lease_handle(owner_lease *lease) { if (lease->file >= 0) { close(lease->file); lease->file = -1; } }
static void close_anchors(anchors *a) {
  int *fds[] = { &a->stage, &a->release, &a->version, &a->locks, &a->root };
  for (size_t i = 0; i < sizeof(fds)/sizeof(fds[0]); i++) if (*fds[i] >= 0) { close(*fds[i]); *fds[i] = -1; }
}
static int same_directory(const struct stat *a, const struct stat *b) {
  return S_ISDIR(a->st_mode) && S_ISDIR(b->st_mode) && a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static int open_directory(int parent, const char *name, struct stat *identity) {
  int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return -1;
  if (fstat(fd, identity) || !S_ISDIR(identity->st_mode)) { int e = errno ? errno : ENOTDIR; close(fd); errno = e; return -1; }
  return fd;
}
static int root_directory(const char *name, struct stat *identity) {
  if (name[0] != '/') { errno = EINVAL; return -1; }
  int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return -1;
  char *copy = strdup(name + 1), *state = NULL; if (!copy) { close(fd); errno = ENOMEM; return -1; }
  char *part = strtok_r(copy, "/", &state);
  while (part) {
    if (!strcmp(part, ".") || !strcmp(part, "..")) { free(copy); close(fd); errno = EINVAL; return -1; }
    struct stat next_identity; int next = open_directory(fd, part, &next_identity), error = errno;
    close(fd); if (next < 0) { free(copy); errno = error; return -1; } fd = next;
    part = strtok_r(NULL, "/", &state);
  }
  free(copy); if (fstat(fd, identity)) { int e = errno; close(fd); errno = e; return -1; } return fd;
}
static int open_anchors(const char *root, const char *stage, anchors *a, int private_stage) {
  struct stat ignored;
  if ((a->root = root_directory(root, &a->r)) < 0 ||
      (a->locks = open_directory(a->root, "locks", &ignored)) < 0 ||
      (a->version = open_directory(a->locks, "v1", &a->v)) < 0 ||
      (a->release = open_directory(a->version, ".release", &a->p)) < 0 ||
      (a->stage = open_directory(private_stage ? a->release : a->version, stage, &a->s)) < 0) return -1;
  if (a->s.st_dev != a->v.st_dev || a->p.st_dev != a->v.st_dev || a->r.st_dev != a->v.st_dev) { errno = EXDEV; return -1; }
  return 0;
}
static int qualified_local_filesystem(int descriptor) {
  struct statfs volume; if (fstatfs(descriptor, &volume)) return 0;
#if defined(__APPLE__)
  return (volume.f_flags & MNT_LOCAL) && (!strcmp(volume.f_fstypename, "apfs") || !strcmp(volume.f_fstypename, "hfs"));
#else
  /* No NFS, SMB, FUSE or unknown remote lease semantics. Overlay is the
     kernel local upper-layer implementation used by isolated Linux hosts. */
  switch ((unsigned long)volume.f_type) {
    case 0xef53UL: case 0x58465342UL: case 0x9123683eUL:
    case 0x01021994UL: case 0x794c7630UL: case 0xf2f52010UL: return 1;
    default: return 0;
  }
#endif
}
static int same_file(const struct stat *a, const struct stat *b) {
  if (!S_ISREG(a->st_mode) || !S_ISREG(b->st_mode) || a->st_dev != b->st_dev || a->st_ino != b->st_ino ||
      a->st_size != b->st_size || a->st_nlink != 1 || b->st_nlink != 1) return 0;
#if defined(__APPLE__)
  return a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
    a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
  return a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
    a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}
static int take_owner_lease(int directory, owner_lease *lease) {
  if (!qualified_local_filesystem(directory)) { errno = ENOTSUP; return -1; }
  /* The published owner is immutable. Local flock does not require write
     access, and recovery must retain the existing shared-reader contract. */
  lease->file = openat(directory, "owner.json", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (lease->file < 0) return -1;
  if (fstat(directory, &lease->directory) || fstat(lease->file, &lease->owner)) return -1;
  if (!S_ISREG(lease->owner.st_mode) || lease->owner.st_nlink != 1 || lease->owner.st_size < 1 || lease->owner.st_size > 4096) { errno = EINVAL; return -1; }
  if (flock(lease->file, LOCK_EX | LOCK_NB)) return errno == EWOULDBLOCK || errno == EAGAIN ? 1 : -1;
  while (lease->used < sizeof(lease->raw)) {
    ssize_t count = read(lease->file, lease->raw + lease->used, sizeof(lease->raw) - lease->used);
    if (count < 0) return -1;
    if (!count) break;
    lease->used += (size_t)count;
  }
  struct stat after, live;
  if (fstat(lease->file, &after) || fstatat(directory, "owner.json", &live, AT_SYMLINK_NOFOLLOW) ||
      !same_file(&lease->owner, &after) || !same_file(&after, &live) || lease->used != (size_t)after.st_size) { errno = ESTALE; return -1; }
  return 0;
}
static int binding(const char *root, const char *stage, anchors *a, int after, const char *public_name) {
  struct stat root_identity, version_identity, release_identity, stage_identity, ignored;
  int rootfd = root_directory(root, &root_identity), locksfd = -1, versionfd = -1, releasefd = -1, code = -1;
  if (rootfd < 0 || !same_directory(&root_identity, &a->r)) goto done;
  if ((locksfd = open_directory(rootfd, "locks", &ignored)) < 0 ||
      (versionfd = open_directory(locksfd, "v1", &version_identity)) < 0 || !same_directory(&version_identity, &a->v) ||
      (releasefd = open_directory(versionfd, ".release", &release_identity)) < 0 || !same_directory(&release_identity, &a->p)) goto done;
  if (fstatat(after ? versionfd : releasefd, after ? public_name : stage, &stage_identity, AT_SYMLINK_NOFOLLOW) ||
      !same_directory(&stage_identity, &a->s)) goto done;
  code = 0;
done:
  if (releasefd >= 0) close(releasefd);
  if (versionfd >= 0) close(versionfd);
  if (locksfd >= 0) close(locksfd);
  if (rootfd >= 0) close(rootfd);
  if (code) errno = ESTALE;
  return code;
}
static int publish_native(const char *root, const char *stage, const char *public_name, double budget, int *published, unsigned long *error, owner_lease *lease) {
  anchors a = { .root = -1, .locks = -1, .version = -1, .release = -1, .stage = -1 };
  double start = monotonic_ms(); int result = -1; *published = 0;
  if (open_anchors(root, stage, &a, 1) || binding(root, stage, &a, 0, public_name) || take_owner_lease(a.stage, lease)) goto done;
  /* Stage contents and its directory entry must precede publication. File
     contents are fsynced by the caller before this directory fsync. */
  if (budget_expired(start, budget)) { errno = ETIMEDOUT; result = 2; goto done; }
  if (fsync(a.stage)) goto done;
  if (budget_expired(start, budget)) { errno = ETIMEDOUT; result = 2; goto done; }
  int moved;
#if defined(__linux__)
#ifdef SYS_renameat2
  moved = (int)syscall(SYS_renameat2, a.release, stage, a.version, public_name, RENAME_NOREPLACE);
#else
  errno = ENOSYS; moved = -1;
#endif
#else
  moved = renameatx_np(a.release, stage, a.version, public_name, RENAME_EXCL);
#endif
  if (moved) { if (errno == EEXIST || errno == ENOTEMPTY) result = 1; goto done; }
  *published = 1;
  if (binding(root, stage, &a, 1, public_name)) goto done;
  if (fsync(a.version) || fsync(a.release)) goto done;
  result = 0;
done:
  *error = result == 0 ? 0 : (unsigned long)errno;
  close_anchors(&a); return result;
}
static int probe_native(const char *root, const char *public_name, owner_lease *lease, unsigned long *error) {
  anchors a = { .root = -1, .locks = -1, .version = -1, .release = -1, .stage = -1 };
  int result = -1;
  if (open_anchors(root, public_name, &a, 0) || binding(root, public_name, &a, 1, public_name)) goto done;
  result = take_owner_lease(a.stage, lease);
  if (result == 0 && binding(root, public_name, &a, 1, public_name)) result = -1;
done:
  *error = result == 0 ? 0 : (unsigned long)errno;
  close_anchors(&a); return result;
}
#else
/* Every child directory is opened relative to a pinned parent HANDLE.
   OPEN_REPARSE_POINT rejects ancestor junction/reparse substitution. */
#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
typedef NTSTATUS (NTAPI *open_relative_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
  PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *set_information_fn)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
_Static_assert(sizeof(void *) == 8 && offsetof(FILE_RENAME_INFO, RootDirectory) == 8 &&
  offsetof(FILE_RENAME_INFO, FileNameLength) == 16 && offsetof(FILE_RENAME_INFO, FileName) == 20,
  "Unexpected Windows relative rename ABI");
typedef ULONG (WINAPI *dos_error_fn)(NTSTATUS);
typedef struct { HANDLE root, locks, version, release, stage; BY_HANDLE_FILE_INFORMATION r, v, p, s; } anchors;
typedef struct { HANDLE file; BY_HANDLE_FILE_INFORMATION owner, directory; unsigned char raw[4097]; size_t used; } owner_lease;
static void initialize_lease(owner_lease *lease) { memset(lease, 0, sizeof(*lease)); lease->file = INVALID_HANDLE_VALUE; }
static void close_lease_handle(owner_lease *lease) { if (lease->file != INVALID_HANDLE_VALUE) { CloseHandle(lease->file); lease->file = INVALID_HANDLE_VALUE; } }
static void close_anchors(anchors *a) {
  HANDLE *fds[] = { &a->stage, &a->release, &a->version, &a->locks, &a->root };
  for (size_t i = 0; i < sizeof(fds)/sizeof(fds[0]); i++) if (*fds[i] != INVALID_HANDLE_VALUE) { CloseHandle(*fds[i]); *fds[i] = INVALID_HANDLE_VALUE; }
}
static int physical_directory(HANDLE h, BY_HANDLE_FILE_INFORMATION *s) {
  if (!GetFileInformationByHandle(h, s)) return 0;
  if (!(s->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (s->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
    SetLastError(ERROR_REPARSE_TAG_INVALID); return 0;
  }
  return 1;
}
static int same_directory(const BY_HANDLE_FILE_INFORMATION *a, const BY_HANDLE_FILE_INFORMATION *b) {
  return a->dwVolumeSerialNumber == b->dwVolumeSerialNumber && a->nFileIndexHigh == b->nFileIndexHigh && a->nFileIndexLow == b->nFileIndexLow;
}
static HANDLE open_directory(HANDLE parent, const wchar_t *name, BY_HANDLE_FILE_INFORMATION *identity, int deleting) {
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  open_relative_fn open_relative = (open_relative_fn)GetProcAddress(module, "NtCreateFile");
  dos_error_fn dos_error = (dos_error_fn)GetProcAddress(module, "RtlNtStatusToDosError");
  if (!open_relative || !dos_error) { SetLastError(ERROR_NOT_SUPPORTED); return INVALID_HANDLE_VALUE; }
  UNICODE_STRING value; value.Buffer = (PWSTR)name; value.Length = (USHORT)(wcslen(name) * sizeof(wchar_t)); value.MaximumLength = value.Length;
  OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &value, OBJ_CASE_INSENSITIVE, parent, NULL);
  IO_STATUS_BLOCK io; HANDLE handle = INVALID_HANDLE_VALUE;
  NTSTATUS status = open_relative(&handle, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE | (deleting ? DELETE : 0),
    &oa, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, NULL, 0);
  if (status < 0) { SetLastError(dos_error(status)); return INVALID_HANDLE_VALUE; }
  if (!physical_directory(handle, identity)) { DWORD e = GetLastError(); CloseHandle(handle); SetLastError(e); return INVALID_HANDLE_VALUE; }
  return handle;
}
static int qualified_local_filesystem(HANDLE directory) {
  wchar_t resolved[32768], filesystem[64];
  DWORD length = GetFinalPathNameByHandleW(directory, resolved, 32768, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (!length || length >= 32768 || wcsncmp(resolved, L"\\\\?\\", 4) || resolved[5] != L':' || resolved[6] != L'\\') return 0;
  wchar_t drive[] = L"C:\\"; drive[0] = resolved[4];
  if (GetDriveTypeW(drive) != DRIVE_FIXED && GetDriveTypeW(drive) != DRIVE_RAMDISK) return 0;
  if (!GetVolumeInformationByHandleW(directory, NULL, 0, NULL, NULL, NULL, filesystem, 64)) return 0;
  return !_wcsicmp(filesystem, L"NTFS");
}
static int same_file(const BY_HANDLE_FILE_INFORMATION *a, const BY_HANDLE_FILE_INFORMATION *b) {
  return !(a->dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
    !(b->dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
    a->nNumberOfLinks == 1 && b->nNumberOfLinks == 1 && same_directory(a, b) &&
    a->nFileSizeHigh == b->nFileSizeHigh && a->nFileSizeLow == b->nFileSizeLow &&
    a->ftLastWriteTime.dwHighDateTime == b->ftLastWriteTime.dwHighDateTime && a->ftLastWriteTime.dwLowDateTime == b->ftLastWriteTime.dwLowDateTime;
}
static HANDLE open_owner_file(HANDLE directory) {
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  open_relative_fn open_relative = (open_relative_fn)GetProcAddress(module, "NtCreateFile");
  dos_error_fn dos_error = (dos_error_fn)GetProcAddress(module, "RtlNtStatusToDosError");
  if (!open_relative || !dos_error) { SetLastError(ERROR_NOT_SUPPORTED); return INVALID_HANDLE_VALUE; }
  UNICODE_STRING value; value.Buffer = L"owner.json"; value.Length = 10 * sizeof(wchar_t); value.MaximumLength = value.Length;
  OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &value, OBJ_CASE_INSENSITIVE, directory, NULL);
  IO_STATUS_BLOCK io; HANDLE handle = INVALID_HANDLE_VALUE;
  /* Read immutable ownership bytes without requiring write permission.
     The lifetime reference is retained separately before publication. */
  NTSTATUS status = open_relative(&handle, GENERIC_READ | SYNCHRONIZE,
    &oa, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
    0x00000040 /* FILE_NON_DIRECTORY_FILE */ | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, NULL, 0);
  if (status < 0) { SetLastError(dos_error(status)); return INVALID_HANDLE_VALUE; }
  if (!SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)) { DWORD e=GetLastError(); CloseHandle(handle); SetLastError(e); return INVALID_HANDLE_VALUE; }
  return handle;
}
static int take_owner_lease(HANDLE directory, owner_lease *lease) {
  if (!qualified_local_filesystem(directory)) { SetLastError(ERROR_NOT_SUPPORTED); return -1; }
  lease->file = open_owner_file(directory); if (lease->file == INVALID_HANDLE_VALUE) return -1;
  if (GetFileType(lease->file) != FILE_TYPE_DISK || !GetFileInformationByHandle(directory, &lease->directory) ||
      !GetFileInformationByHandle(lease->file, &lease->owner)) return -1;
  if (!same_file(&lease->owner, &lease->owner) || lease->owner.nFileSizeHigh || !lease->owner.nFileSizeLow || lease->owner.nFileSizeLow > 4096) { SetLastError(ERROR_FILE_INVALID); return -1; }
  FILE_BASIC_INFO before_basic, after_basic;
  if (!GetFileInformationByHandleEx(lease->file, FileBasicInfo, &before_basic, sizeof(before_basic))) return -1;
  while (lease->used < sizeof(lease->raw)) {
    DWORD count = 0;
    if (!ReadFile(lease->file, lease->raw + lease->used, (DWORD)(sizeof(lease->raw) - lease->used), &count, NULL)) return -1;
    if (!count) break; lease->used += count;
  }
  BY_HANDLE_FILE_INFORMATION after, live; HANDLE current = open_owner_file(directory);
  int valid = current != INVALID_HANDLE_VALUE && GetFileInformationByHandle(current, &live) &&
    GetFileInformationByHandle(lease->file, &after) && GetFileInformationByHandleEx(lease->file, FileBasicInfo, &after_basic, sizeof(after_basic)) &&
    same_file(&lease->owner, &after) && same_file(&after, &live) && lease->used == after.nFileSizeLow &&
    before_basic.ChangeTime.QuadPart == after_basic.ChangeTime.QuadPart && before_basic.LastWriteTime.QuadPart == after_basic.LastWriteTime.QuadPart;
  if (current != INVALID_HANDLE_VALUE) CloseHandle(current);
  if (!valid) { SetLastError(ERROR_FILE_INVALID); return -1; }
  /* NTFS does not permit moving a directory containing an open file, even
     with FILE_SHARE_DELETE. Retain a kernel object keyed by these immutable
     physical identities instead. Object existence, never event state, is
     the lifetime proof. The Global namespace spans interactive sessions. */
  if(lease->owner.dwVolumeSerialNumber!=lease->directory.dwVolumeSerialNumber) { SetLastError(ERROR_NOT_SAME_DEVICE); return -1; }
  unsigned long long owner_id=((unsigned long long)lease->owner.nFileIndexHigh<<32)|lease->owner.nFileIndexLow;
  unsigned long long directory_id=((unsigned long long)lease->directory.nFileIndexHigh<<32)|lease->directory.nFileIndexLow;
  wchar_t event_name[160];
  if(_snwprintf_s(event_name,160,_TRUNCATE,L"Global\\KnowledgeOwnerLease-v1-%08lX-%016llX-%016llX",
      (unsigned long)lease->owner.dwVolumeSerialNumber,owner_id,directory_id)<0) { SetLastError(ERROR_INVALID_NAME); return -1; }
  close_lease_handle(lease);
  SetLastError(ERROR_SUCCESS);
  HANDLE lifetime=CreateEventExW(NULL,event_name,CREATE_EVENT_MANUAL_RESET,SYNCHRONIZE);
  DWORD created_error=GetLastError();
  if(!lifetime) {SetLastError(created_error);return -1;}
  if(created_error!=ERROR_SUCCESS) {
    CloseHandle(lifetime);SetLastError(created_error);
    return created_error==ERROR_ALREADY_EXISTS?1:-1;
  }
  if(!SetHandleInformation(lifetime,HANDLE_FLAG_INHERIT,0)) {
    DWORD e=GetLastError();CloseHandle(lifetime);SetLastError(e);return -1;
  }
  lease->file=lifetime;
  return 0;
}
static wchar_t *wide(const char *input) {
  int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, NULL, 0); if (!size || size > 32767) return NULL;
  wchar_t *result = (wchar_t *)malloc((size_t)size * sizeof(wchar_t)); if (!result) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, result, size)) { free(result); return NULL; }
  for (int i = 0; i < size; i++) if (result[i] == L'/') result[i] = L'\\';
  return result;
}
static HANDLE root_directory(const wchar_t *input, BY_HANDLE_FILE_INFORMATION *identity) {
  const wchar_t *p = input; if (!wcsncmp(p, L"\\\\?\\", 4)) p += 4;
  if (!((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) || p[1] != L':' || p[2] != L'\\') {
    SetLastError(ERROR_NOT_SUPPORTED); return INVALID_HANDLE_VALUE;
  }
  wchar_t drive[] = L"\\\\?\\C:\\"; drive[4] = p[0];
  HANDLE fd = CreateFileW(drive, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (fd == INVALID_HANDLE_VALUE || !physical_directory(fd, identity)) { if (fd != INVALID_HANDLE_VALUE) CloseHandle(fd); return INVALID_HANDLE_VALUE; }
  p += 3;
  while (*p) {
    const wchar_t *end = wcschr(p, L'\\'); size_t length = end ? (size_t)(end-p) : wcslen(p);
    if (!length) { p++; continue; }
    if (length > 255 || (length == 1 && p[0] == L'.') || (length == 2 && p[0] == L'.' && p[1] == L'.')) { CloseHandle(fd); SetLastError(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    wchar_t part[256]; memcpy(part, p, length*sizeof(wchar_t)); part[length] = 0;
    HANDLE next = open_directory(fd, part, identity, 0); DWORD error = GetLastError(); CloseHandle(fd);
    if (next == INVALID_HANDLE_VALUE) { SetLastError(error); return INVALID_HANDLE_VALUE; } fd = next;
    p += length; if (*p == L'\\') p++;
  }
  return fd;
}
static int open_anchors(const wchar_t *root, const wchar_t *stage, anchors *a, int private_stage) {
  BY_HANDLE_FILE_INFORMATION ignored;
  if ((a->root = root_directory(root, &a->r)) == INVALID_HANDLE_VALUE ||
      (a->locks = open_directory(a->root, L"locks", &ignored, 0)) == INVALID_HANDLE_VALUE ||
      (a->version = open_directory(a->locks, L"v1", &a->v, 0)) == INVALID_HANDLE_VALUE ||
      (a->release = open_directory(a->version, L".release", &a->p, 0)) == INVALID_HANDLE_VALUE ||
      (a->stage = open_directory(private_stage ? a->release : a->version, stage, &a->s, private_stage)) == INVALID_HANDLE_VALUE) return -1;
  if (a->s.dwVolumeSerialNumber != a->v.dwVolumeSerialNumber || a->p.dwVolumeSerialNumber != a->v.dwVolumeSerialNumber || a->r.dwVolumeSerialNumber != a->v.dwVolumeSerialNumber) {
    SetLastError(ERROR_NOT_SAME_DEVICE); return -1;
  }
  return 0;
}
static int binding(const wchar_t *root, const wchar_t *stage, const wchar_t *public_name, anchors *a, int after) {
  BY_HANDLE_FILE_INFORMATION r, v, p, s, ignored;
  HANDLE rh = root_directory(root, &r), lh = INVALID_HANDLE_VALUE, vh = INVALID_HANDLE_VALUE, ph = INVALID_HANDLE_VALUE, sh = INVALID_HANDLE_VALUE;
  int result = -1;
  if (rh == INVALID_HANDLE_VALUE || !same_directory(&r, &a->r)) goto done;
  lh = open_directory(rh, L"locks", &ignored, 0); if (lh == INVALID_HANDLE_VALUE) goto done;
  vh = open_directory(lh, L"v1", &v, 0); if (vh == INVALID_HANDLE_VALUE || !same_directory(&v, &a->v)) goto done;
  ph = open_directory(vh, L".release", &p, 0); if (ph == INVALID_HANDLE_VALUE || !same_directory(&p, &a->p)) goto done;
  sh = open_directory(after ? vh : ph, after ? public_name : stage, &s, 0);
  if (sh != INVALID_HANDLE_VALUE && same_directory(&s, &a->s)) result = 0;
done:
  if (sh != INVALID_HANDLE_VALUE) CloseHandle(sh);
  if (ph != INVALID_HANDLE_VALUE) CloseHandle(ph);
  if (vh != INVALID_HANDLE_VALUE) CloseHandle(vh);
  if (lh != INVALID_HANDLE_VALUE) CloseHandle(lh);
  if (rh != INVALID_HANDLE_VALUE) CloseHandle(rh);
  if (result) SetLastError(ERROR_FILE_INVALID);
  return result;
}
static int publish_native(const char *root_input, const char *stage_input, const char *public_input, double budget, int *published, unsigned long *error, owner_lease *lease) {
  double start = monotonic_ms();
  wchar_t *root = wide(root_input), *stage = wide(stage_input), *public_name = wide(public_input);
  anchors a = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
  FILE_RENAME_INFO *rename_info = NULL; int result = -1; *published = 0;
  if (!root || !stage || !public_name || open_anchors(root, stage, &a, 1) || binding(root, stage, public_name, &a, 0) || take_owner_lease(a.stage, lease)) goto done;
  size_t length = wcslen(public_name)*sizeof(wchar_t), size = sizeof(FILE_RENAME_INFO) + length;
  rename_info = (FILE_RENAME_INFO *)calloc(1, size); if (!rename_info) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto done; }
  rename_info->ReplaceIfExists = FALSE; rename_info->RootDirectory = a.version;
  rename_info->FileNameLength = (DWORD)length; memcpy(rename_info->FileName, public_name, length);
  if (budget_expired(start, budget)) { SetLastError(ERROR_TIMEOUT); result = 2; goto done; }
  /* The Win32 FileRenameInfo wrapper rejects a non-NULL RootDirectory on
     actual Windows runners, despite the structure documentation. Do not
     turn this into a by-path rename: the pinned destination HANDLE is the
     containment boundary. The NT FileRenameInformation service accepts
     precisely this bounded relative name and preserves no-replace. */
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  set_information_fn set_information = (set_information_fn)GetProcAddress(module, "NtSetInformationFile");
  dos_error_fn dos_error = (dos_error_fn)GetProcAddress(module, "RtlNtStatusToDosError");
  if (!set_information || !dos_error) { SetLastError(ERROR_NOT_SUPPORTED); goto done; }
  IO_STATUS_BLOCK io; memset(&io, 0, sizeof(io));
  NTSTATUS status = set_information(a.stage, &io, rename_info, (ULONG)size, (FILE_INFORMATION_CLASS)10 /* FileRenameInformation */);
  if (status != 0 || io.Status != 0) {
    /* Our HANDLE is synchronous. A pending return must nevertheless remain
       publication uncertainty, never permission to clean or admit work. */
    if (status == (NTSTATUS)0x00000103L) *published = 1;
    DWORD code = dos_error(status != 0 ? status : io.Status);
    if (code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS) result = 1;
    SetLastError(code); goto done;
  }
  *published = 1;
  if (binding(root, stage, public_name, &a, 1)) goto done;
  /* Owner files are flushed by the caller. Windows has no supported directory
     fsync equivalent here: process-crash atomicity is asserted, power-loss
     durability is not inferred from this call. */
  result = 0;
done:
  *error = result == 0 ? 0 : GetLastError(); free(rename_info); close_anchors(&a); free(root); free(stage); free(public_name); return result;
}
static int probe_native(const char *root_input, const char *public_input, owner_lease *lease, unsigned long *error) {
  wchar_t *root=wide(root_input), *public_name=wide(public_input);
  anchors a={INVALID_HANDLE_VALUE,INVALID_HANDLE_VALUE,INVALID_HANDLE_VALUE,INVALID_HANDLE_VALUE,INVALID_HANDLE_VALUE};
  int result=-1;
  if (!root || !public_name || open_anchors(root,public_name,&a,0) || binding(root,public_name,public_name,&a,1)) goto done;
  result=take_owner_lease(a.stage,lease);
  if (result==0 && binding(root,public_name,public_name,&a,1)) result=-1;
done:
  *error=result==0?0:GetLastError(); close_anchors(&a); free(root); free(public_name); return result;
}
#endif

// No JavaScript finalizer owns these handles. A live writer lease survives
// garbage collection, lost JS references and worker-context teardown; only
// explicit post-release close or process death closes it. Registry mutation
// uses a short mutex and never holds that mutex across filesystem I/O.
typedef struct lease_entry { uint64_t id; owner_lease lease; struct lease_entry *next; } lease_entry;
static lease_entry *leases=NULL;
static uint64_t next_lease=1;
#if defined(_WIN32)
static SRWLOCK lease_mutex=SRWLOCK_INIT;
#define LOCK_TABLE() AcquireSRWLockExclusive(&lease_mutex)
#define UNLOCK_TABLE() ReleaseSRWLockExclusive(&lease_mutex)
#else
static pthread_mutex_t lease_mutex=PTHREAD_MUTEX_INITIALIZER;
#define LOCK_TABLE() pthread_mutex_lock(&lease_mutex)
#define UNLOCK_TABLE() pthread_mutex_unlock(&lease_mutex)
#endif
static uint64_t retain_lease(owner_lease *lease) {
  lease_entry *entry=(lease_entry *)malloc(sizeof(*entry)); if(!entry)return 0;
  entry->lease=*lease;
  LOCK_TABLE();
  if(next_lease>=9007199254740991ULL){UNLOCK_TABLE();free(entry);return 0;}
  entry->id=next_lease++; uint64_t id=entry->id; entry->next=leases; leases=entry;
  UNLOCK_TABLE();
  initialize_lease(lease); return id;
}
static void lease_identity(napi_env env,napi_value result,const owner_lease *lease) {
  napi_value owner,directory,raw; napi_create_object(env,&owner); napi_create_object(env,&directory);
  char dev[32],ino[32],dir_dev[32],dir_ino[32];
#if defined(_WIN32)
  snprintf(dev,sizeof(dev),"%lu",(unsigned long)lease->owner.dwVolumeSerialNumber);
  snprintf(ino,sizeof(ino),"%llu",((unsigned long long)lease->owner.nFileIndexHigh<<32)|lease->owner.nFileIndexLow);
  snprintf(dir_dev,sizeof(dir_dev),"%lu",(unsigned long)lease->directory.dwVolumeSerialNumber);
  snprintf(dir_ino,sizeof(dir_ino),"%llu",((unsigned long long)lease->directory.nFileIndexHigh<<32)|lease->directory.nFileIndexLow);
#else
  snprintf(dev,sizeof(dev),"%llu",(unsigned long long)lease->owner.st_dev); snprintf(ino,sizeof(ino),"%llu",(unsigned long long)lease->owner.st_ino);
  snprintf(dir_dev,sizeof(dir_dev),"%llu",(unsigned long long)lease->directory.st_dev); snprintf(dir_ino,sizeof(dir_ino),"%llu",(unsigned long long)lease->directory.st_ino);
#endif
  field(env,owner,"dev",dev);field(env,owner,"ino",ino);field(env,directory,"dev",dir_dev);field(env,directory,"ino",dir_ino);
  napi_set_named_property(env,result,"owner_identity",owner);napi_set_named_property(env,result,"directory_identity",directory);
  napi_create_buffer_copy(env,lease->used,lease->raw,NULL,&raw);napi_set_named_property(env,result,"owner_bytes",raw);
}

static napi_value close_lease(napi_env env,napi_callback_info callback) {
  size_t count=1;napi_value args[1];double value;
  if(napi_get_cb_info(env,callback,&count,args,NULL,NULL)!=napi_ok||count!=1||napi_get_value_double(env,args[0],&value)!=napi_ok||
     !isfinite(value)||value<1||value>=9007199254740991.0||floor(value)!=value)return fail(env,"lock_native_argument_invalid","Invalid native lease token.",0);
  uint64_t id=(uint64_t)value;lease_entry *found=NULL;
  LOCK_TABLE();lease_entry **link=&leases;while(*link){if((*link)->id==id){found=*link;*link=found->next;break;}link=&(*link)->next;}UNLOCK_TABLE();
  if(found){close_lease_handle(&found->lease);free(found);}
  napi_value result;napi_get_boolean(env,found!=NULL,&result);return result;
}

static napi_value probe_lease(napi_env env,napi_callback_info callback) {
  size_t count=2;napi_value args[2];
  if(napi_get_cb_info(env,callback,&count,args,NULL,NULL)!=napi_ok||count!=2)return fail(env,"lock_native_argument_invalid","Expected root and public basename.",0);
  char *root=string_argument(env,args[0],65535),*name=string_argument(env,args[1],240);
  if(!root||!name||!basename_valid(name,0)){free(root);free(name);return fail(env,"lock_native_argument_invalid","Invalid contained lease path.",0);}
  owner_lease lease;initialize_lease(&lease);unsigned long error=0;int status=probe_native(root,name,&lease,&error);free(root);free(name);
  napi_value result,number;napi_create_object(env,&result);field(env,result,"status",status==0?"acquired":status==1?"busy":"failed");
  napi_create_double(env,(double)error,&number);napi_set_named_property(env,result,"native_error",number);
  if(status==0){
    lease_identity(env,result,&lease);uint64_t id=retain_lease(&lease);
    if(!id){field(env,result,"status","failed");field(env,result,"reason","lease_table_exhausted");}
    else{napi_create_double(env,(double)id,&number);napi_set_named_property(env,result,"lease_id",number);}
  }
  close_lease_handle(&lease);return result;
}

static napi_value publish(napi_env env, napi_callback_info callback) {
  size_t count = 4; napi_value args[4]; double budget;
  if (napi_get_cb_info(env, callback, &count, args, NULL, NULL) != napi_ok || count != 4 ||
      napi_get_value_double(env, args[3], &budget) != napi_ok || !isfinite(budget) || budget <= 0 || budget > 600000) return fail(env, "lock_native_argument_invalid", "Expected root, private stage basename, public basename, positive admission budget.", 0);
  char *root = string_argument(env, args[0], 65535), *stage = string_argument(env, args[1], 240), *public_name = string_argument(env, args[2], 240);
  if (!root || !stage || !public_name || !basename_valid(stage, 1) || !basename_valid(public_name, 0)) {
    free(root); free(stage); free(public_name); return fail(env, "lock_native_argument_invalid", "Invalid contained publication path.", 0);
  }
  int published = 0; unsigned long native_error = 0; owner_lease lease; initialize_lease(&lease);
  int status = publish_native(root, stage, public_name, budget, &published, &native_error, &lease);
  free(root); free(stage); free(public_name);
  napi_value value; napi_create_object(env, &value);
  field(env, value, "status", status == 0 ? "published" : status == 1 ? "exists" : status == 2 ? "budget_exhausted" : "failed");
  field(env, value, "method", "anchored_exclusive_directory.v1");
  napi_value boolean, number; napi_get_boolean(env, published, &boolean); napi_set_named_property(env, value, "published", boolean);
  napi_create_double(env, (double)native_error, &number); napi_set_named_property(env, value, "native_error", number);
  if(published){
    lease_identity(env,value,&lease);uint64_t id=retain_lease(&lease);
    if(!id){field(env,value,"status","failed");field(env,value,"reason","lease_table_exhausted");}
    else{napi_create_double(env,(double)id,&number);napi_set_named_property(env,value,"lease_id",number);}
  }
  close_lease_handle(&lease);
  return value;
}
/* Independent executable trust check. The package's pinned N-API code checks
 * the candidate helper; an executable's own --probe reply cannot authenticate
 * permissions on itself. All metadata and bytes come from anchored descriptors.
 * Invoke only in the isolated preparer/storage process: a real kernel I/O stall
 * can outlive the logical budget and must not block the monitor's stop path. */
#if defined(__APPLE__)
static int protected_same(const struct stat *a,const struct stat *b,int leaf) {
  return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_mode==b->st_mode &&
    a->st_uid==b->st_uid && a->st_gid==b->st_gid && (!leaf ||
    (a->st_size==b->st_size && a->st_nlink==b->st_nlink &&
      a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec &&
      a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec));
}
static int protected_acl_fd(int fd,const struct stat *expected,int leaf) {
  filesec_t metadata=filesec_init();if(!metadata)return 0;
  struct stat observed;int present=0,safe=0;acl_t acl=NULL;
  if(fstatx_np(fd,&observed,metadata) || !protected_same(expected,&observed,leaf) ||
      filesec_query_property(metadata,FILESEC_ACL,&present))goto done;
  if(!present){safe=1;goto done;}
  if(filesec_get_property(metadata,FILESEC_ACL,&acl) || !acl)goto done;
  /* Darwin returns -1/EINVAL after the last entry; this is not Linux's 0 end.
   * A bounded index also makes malformed or unexpectedly huge ACLs fail shut. */
  for(int index=0;index<1024;index++) {
    acl_entry_t entry;errno=0;
    if(acl_get_entry(acl,index,&entry)) {if(errno==EINVAL)safe=1;goto done;}
    acl_tag_t tag;acl_permset_t permissions;
    if(acl_get_tag_type(entry,&tag) || acl_get_permset(entry,&permissions))goto done;
    if(tag==ACL_EXTENDED_DENY)continue;
    if(tag!=ACL_EXTENDED_ALLOW)goto done;
    const acl_perm_t writes[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,
      ACL_WRITE_ATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER};
    for(size_t i=0;i<sizeof(writes)/sizeof(writes[0]);i++)
      if(acl_get_perm_np(permissions,writes[i])!=0)goto done;
  }
done:
  if(acl)acl_free(acl);filesec_free(metadata);return safe;
}
static int protected_metadata(int fd,struct stat *st,int leaf,int sticky_tmp) {
  if(fstat(fd,st) || st->st_uid!=0 || (st->st_mode&0022 && !sticky_tmp))return 0;
  if(leaf ? (!S_ISREG(st->st_mode)||st->st_nlink!=1||(st->st_mode&06000)||!(st->st_mode&0111))
      : (!S_ISDIR(st->st_mode)||(sticky_tmp&&!(st->st_mode&S_ISVTX))))return 0;
  return protected_acl_fd(fd,st,leaf);
}
static void protected_u64(napi_env env,napi_value result,const char *name,uint64_t value) {
  char buffer[32];snprintf(buffer,sizeof(buffer),"%llu",(unsigned long long)value);field(env,result,name,buffer);
}
static napi_value verify_protected_executable(napi_env env,napi_callback_info callback) {
  napi_value args[3];size_t count=3;double maximum=0,budget=0;char *path=NULL,*cursor=NULL;
  if(napi_get_cb_info(env,callback,&count,args,NULL,NULL)!=napi_ok||count!=3 ||
      !(path=string_argument(env,args[0],4096)) ||
      napi_get_value_double(env,args[1],&maximum)!=napi_ok||!isfinite(maximum)||maximum<1||maximum>268435456||floor(maximum)!=maximum ||
      napi_get_value_double(env,args[2],&budget)!=napi_ok||!isfinite(budget)||budget<1||budget>600000) {
    free(path);return fail(env,"darwin_protected_argument_invalid","Expected canonical path, byte cap and remaining budget.",0);
  }
  int fds[257],used=0,ok=0;char *names[257]={0};struct stat states[257];
  for(size_t i=0;i<257;i++)fds[i]=-1;
  unsigned long native_error=0;const char *reason="darwin_protected_path_unsafe";
  double start=monotonic_ms();size_t length=strlen(path);
  if(path[0]!='/'||length<2||path[length-1]=='/'||strstr(path,"//")||strchr(path,'\\'))goto done;
  for(size_t i=0;i<length;i++)if((unsigned char)path[i]<32 || (unsigned char)path[i]==127)goto done;
  /* Directory anchors need search and metadata access, not directory listing.
   * O_RDONLY would reject a safe root-owned 0711 ancestor for ordinary callers.
   * Darwin O_SEARCH retains an anchored directory FD without granting reads;
   * the executable leaf still requires O_RDONLY for its exact byte hash. */
  fds[0]=open("/",O_SEARCH|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);used=1;
  if(fds[0]<0 || !protected_metadata(fds[0],&states[0],0,0))goto done;
  cursor=path+1;
  while(*cursor) {
    if(budget_expired(start,budget)){reason="darwin_protected_budget_exceeded";goto done;}
    if(used>=257)goto done;
    char *next=strchr(cursor,'/');int leaf=next==NULL;
    if(next)*next=0;
    if(!*cursor||!strcmp(cursor,".")||!strcmp(cursor,".."))goto done;
    names[used]=cursor;struct stat named;
    if(fstatat(fds[used-1],cursor,&named,AT_SYMLINK_NOFOLLOW)||S_ISLNK(named.st_mode))goto done;
    fds[used]=openat(fds[used-1],cursor,(leaf?O_RDONLY:O_SEARCH)|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    int index=used++;
    int sticky_tmp=index==2&&!strcmp(names[1],"private")&&!strcmp(cursor,"tmp")&&!leaf;
    if(fds[index]<0 || !protected_metadata(fds[index],&states[index],leaf,sticky_tmp) ||
        !protected_same(&named,&states[index],leaf))goto done;
    if(leaf)break;cursor=next+1;
  }
  if(used<2 || !S_ISREG(states[used-1].st_mode) || states[used-1].st_size<1 ||
      (uint64_t)states[used-1].st_size>(uint64_t)maximum)goto done;
  unsigned char block[65536],digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256_CTX hash;
  if(CC_SHA256_Init(&hash)!=1)goto done;
  off_t offset=0,bytes=states[used-1].st_size;
  while(offset<bytes) {
    if(budget_expired(start,budget)){reason="darwin_protected_budget_exceeded";goto done;}
    size_t wanted=(uint64_t)(bytes-offset)>sizeof(block)?sizeof(block):(size_t)(bytes-offset);
    ssize_t got=pread(fds[used-1],block,wanted,offset);
    if(got<0&&errno==EINTR)continue;
    if(got<=0||CC_SHA256_Update(&hash,block,(CC_LONG)got)!=1)goto done;
    offset+=got;
  }
  for(;;) {
    if(budget_expired(start,budget)){reason="darwin_protected_budget_exceeded";goto done;}
    ssize_t extra=pread(fds[used-1],block,1,bytes);
    if(extra<0&&errno==EINTR)continue;if(extra!=0)goto done;break;
  }
  if(CC_SHA256_Final(digest,&hash)!=1)goto done;
  for(int i=used-1;i>=0;i--) {
    if(budget_expired(start,budget)){reason="darwin_protected_budget_exceeded";goto done;}
    struct stat after,named;int leaf=i==used-1;
    if(fstat(fds[i],&after)||!protected_same(&states[i],&after,leaf)||!protected_acl_fd(fds[i],&after,leaf))goto done;
    if(i>0 && (fstatat(fds[i-1],names[i],&named,AT_SYMLINK_NOFOLLOW)||!protected_same(&after,&named,leaf)))goto done;
    if(i==0 && (lstat("/",&named)||!protected_same(&after,&named,0)))goto done;
  }
  if(budget_expired(start,budget)){reason="darwin_protected_budget_exceeded";goto done;}ok=1;
done:
  native_error=(unsigned long)errno;
  for(int i=used-1;i>=0;i--)if(fds[i]>=0)close(fds[i]);
  free(path);
  if(!ok)return fail(env,reason,"Protected executable metadata, ACL or stable bytes could not be confirmed.",native_error);
  napi_value result;napi_create_object(env,&result);
  field(env,result,"schema","knowledge-darwin-protected-executable.v1");field(env,result,"status","verified");
  char hexadecimal[65];for(unsigned i=0;i<32;i++)snprintf(hexadecimal+i*2,3,"%02x",digest[i]);
  field(env,result,"sha256",hexadecimal);
  protected_u64(env,result,"device",(uint64_t)states[used-1].st_dev);
  protected_u64(env,result,"inode",(uint64_t)states[used-1].st_ino);
  protected_u64(env,result,"bytes",(uint64_t)states[used-1].st_size);
  protected_u64(env,result,"ctime_sec",(uint64_t)states[used-1].st_ctimespec.tv_sec);
  protected_u64(env,result,"ctime_nsec",(uint64_t)states[used-1].st_ctimespec.tv_nsec);
  protected_u64(env,result,"mtime_sec",(uint64_t)states[used-1].st_mtimespec.tv_sec);
  protected_u64(env,result,"mtime_nsec",(uint64_t)states[used-1].st_mtimespec.tv_nsec);
  return result;
}
#else
static napi_value verify_protected_executable(napi_env env,napi_callback_info callback) {
  (void)callback;return fail(env,"darwin_protected_platform_unsupported","Darwin ACL observation requires Darwin.",0);
}
#endif
NAPI_MODULE_INIT() {
  napi_property_descriptor definitions[] = {
    { "info", NULL, info, NULL, NULL, NULL, napi_default, NULL },
    { "publish", NULL, publish, NULL, NULL, NULL, napi_default, NULL }
    ,{ "probeLease", NULL, probe_lease, NULL, NULL, NULL, napi_default, NULL }
    ,{ "closeLease", NULL, close_lease, NULL, NULL, NULL, napi_default, NULL }
    ,{ "verifyProtectedExecutable", NULL, verify_protected_executable, NULL, NULL, NULL, napi_default, NULL }
  };
  napi_define_properties(env, exports, sizeof(definitions)/sizeof(definitions[0]), definitions); return exports;
}
