/* Disposable-runner fixture provisioning, never a production auto-installer.
 * Creates ONE previously absent leaf below an already protected parent. It
 * does not create directory-service accounts/groups or edit an existing ACL.
 * Compile on macOS: cc -std=c11 -D_DARWIN_C_SOURCE -Wall -Wextra this.c -o helper
 * sudo GITHUB_ACTIONS=true helper /protected/new-project owner_uid reserved_gid
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <membership.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static bool number(const char *text,uint32_t *out) {
    if(!text||!*text)return false;uint64_t n=0;
    for(const char *p=text;*p;p++){if(*p<'0'||*p>'9'||n>UINT32_MAX/10)return false;n=n*10+(unsigned)(*p-'0');if(n>UINT32_MAX)return false;}
    *out=(uint32_t)n;return true;
}
static bool parent_safe(const char *path) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX||strstr(path,"//")||strstr(path,"/../")||strstr(path,"/./")
        ||strchr(path,'\n')||strchr(path,'\r')||strchr(path,'"')||strchr(path,'\\'))return false;
    char copy[PATH_MAX];strcpy(copy,path);char *last=strrchr(copy,'/');if(!last||last==copy||!last[1])return false;*last=0;
    for(char *p=copy+1;;p++)if(*p=='/'||!*p){char end=*p;*p=0;struct stat s;
        bool temporary=!strcmp(copy,"/private/tmp");
        if(lstat(copy,&s)||!S_ISDIR(s.st_mode)||s.st_uid!=0||((s.st_mode&0022)&&!(temporary&&(s.st_mode&S_ISVTX))))return false;
        if(!temporary){filesec_t metadata=filesec_init();int present=0;acl_t ancestor=NULL;
            bool safe=metadata&&lstatx_np(copy,&s,metadata)==0&&filesec_query_property(metadata,FILESEC_ACL,&present)==0;
            if(safe&&present)safe=filesec_get_property(metadata,FILESEC_ACL,&ancestor)==0&&ancestor;
            if(metadata)filesec_free(metadata);
            if(safe&&present){acl_entry_t entry;int next=ACL_FIRST_ENTRY;
                while(safe&&acl_get_entry(ancestor,next,&entry)==0){next=ACL_NEXT_ENTRY;acl_tag_t tag;acl_permset_t perms;
                    safe=acl_get_tag_type(entry,&tag)==0&&acl_get_permset(entry,&perms)==0;
                    acl_perm_t writes[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,ACL_WRITE_ATTRIBUTES,
                        ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER};
                    if(safe&&tag==ACL_EXTENDED_ALLOW)for(unsigned i=0;safe&&i<sizeof(writes)/sizeof(writes[0]);i++)safe=acl_get_perm_np(perms,writes[i])==0;
                }}
            if(ancestor)acl_free(ancestor);if(!safe)return false;}
        *p=end;if(!end)break;}
    struct stat st;errno=0;return lstat(path,&st)<0&&errno==ENOENT;
}
static bool add_acl(acl_t *acl,const uuid_t uuid) {
    acl_entry_t entry;acl_permset_t permissions;acl_flagset_t flags;
    if(acl_create_entry(acl,&entry)||acl_set_tag_type(entry,ACL_EXTENDED_ALLOW)||acl_set_qualifier(entry,uuid)
        ||acl_get_permset(entry,&permissions)||acl_clear_perms(permissions)||acl_get_flagset_np(entry,&flags)
        ||acl_clear_flags_np(flags))return false;
    acl_perm_t rights[]={ACL_READ_DATA,ACL_WRITE_DATA,ACL_EXECUTE,ACL_DELETE,ACL_APPEND_DATA,ACL_DELETE_CHILD,
        ACL_READ_ATTRIBUTES,ACL_WRITE_ATTRIBUTES,ACL_READ_EXTATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_READ_SECURITY};
    for(unsigned i=0;i<sizeof(rights)/sizeof(rights[0]);i++)if(acl_add_perm(permissions,rights[i]))return false;
    return !acl_set_permset(entry,permissions)&&!acl_add_flag_np(flags,ACL_ENTRY_FILE_INHERIT)
        &&!acl_add_flag_np(flags,ACL_ENTRY_DIRECTORY_INHERIT)&&!acl_set_flagset_np(entry,flags);
}
int main(int argc,char **argv) {
    uint32_t owner=0,group=0;const char *stage="arguments";bool ok=false;int fd=-1;acl_t acl=NULL;
    uuid_t owner_uuid,group_uuid;uuid_string_t owner_text,group_text;struct stat st={0};
    if(argc!=4||getuid()!=0||geteuid()!=0||!getenv("GITHUB_ACTIONS")||strcmp(getenv("GITHUB_ACTIONS"),"true")
        ||!number(argv[2],&owner)||!owner||owner>=1000000000u||!number(argv[3],&group)
        ||group<2000000000u||group>=2100000000u||!parent_safe(argv[1]))goto done;
    stage="administrator_uuid_binding";id_t inverse=0;int type=0;
    if(mbr_uid_to_uuid(owner,owner_uuid)||mbr_gid_to_uuid(group,group_uuid)||uuid_is_null(owner_uuid)||uuid_is_null(group_uuid)
        ||uuid_compare(owner_uuid,group_uuid)==0||mbr_uuid_to_id(group_uuid,&inverse,&type)
        ||(uint32_t)inverse!=group||type!=ID_TYPE_GID)goto done;
    stage="new_fixture_leaf";
    if(mkdir(argv[1],0770)||(fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC))<0
        ||fchown(fd,(uid_t)owner,(gid_t)group)||fchmod(fd,0770))goto done;
    stage="inherited_fixture_acl";acl=acl_init(2);
    if(!acl||!add_acl(&acl,owner_uuid)||!add_acl(&acl,group_uuid)||acl_set_fd_np(fd,acl,ACL_TYPE_EXTENDED)
        ||fstat(fd,&st)||fsync(fd))goto done;
    uuid_unparse_lower(owner_uuid,owner_text);uuid_unparse_lower(group_uuid,group_text);ok=true;
done:
    if(acl)acl_free(acl);if(fd>=0)close(fd);
    if(ok){printf("{\"ok\":true,\"owner_uid\":%u,\"group_gid\":%u,\"owner_uuid\":\"%s\",\"group_uuid\":\"%s\","
        "\"root\":\"%s\",\"root_device\":\"%llu\",\"root_inode\":\"%llu\",\"root_mode\":%u,"
        "\"group_policy\":\"admin_reserved_workspace_group.v1\"}\n",owner,group,owner_text,group_text,argv[1],
        (unsigned long long)st.st_dev,(unsigned long long)st.st_ino,(unsigned)(st.st_mode&07777));return 0;}
    printf("{\"ok\":false,\"stage\":\"%s\",\"errno\":%d}\n",stage,errno);return 1;
}
