#import <Foundation/Foundation.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <errno.h>
int main(int argc,char **argv){@autoreleasepool{
    NSMutableArray *rows=[NSMutableArray array];
    for(int i=1;i<argc;i++){
        NSString *value=@(argv[i]);
        [rows addObject:@{@"input":value,@"standardized":value.stringByStandardizingPath,
                         @"resolved":value.stringByResolvingSymlinksInPath}];
        NSString *prefix=@"/";
        for(NSString *part in [value pathComponents]){
            if([part isEqual:@"/"])continue;
            prefix=[prefix stringByAppendingPathComponent:part];
            struct stat stat;errno=0;int rc=lstat(prefix.fileSystemRepresentation,&stat);int se=errno;
            errno=0;acl_t acl=acl_get_file(prefix.fileSystemRepresentation,ACL_TYPE_EXTENDED);int ae=errno;
            [rows addObject:@{@"appended_prefix":prefix,@"lstat_rc":@(rc),@"lstat_errno":@(se),
                @"symlink":@(rc==0&&S_ISLNK(stat.st_mode)),@"acl_present":@(acl!=NULL),@"acl_errno":@(ae)}];
            if(acl)acl_free(acl);
        }
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:rows options:NSJSONWritingSortedKeys error:NULL];
    return fwrite(data.bytes,1,data.length,stdout)==data.length?0:1;
}}
