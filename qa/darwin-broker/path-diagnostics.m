#import <Foundation/Foundation.h>
int main(int argc,char **argv){@autoreleasepool{
    NSMutableArray *rows=[NSMutableArray array];
    for(int i=1;i<argc;i++){
        NSString *value=@(argv[i]);
        [rows addObject:@{@"input":value,@"standardized":value.stringByStandardizingPath,
                         @"resolved":value.stringByResolvingSymlinksInPath}];
    }
    NSData *data=[NSJSONSerialization dataWithJSONObject:rows options:NSJSONWritingSortedKeys error:NULL];
    return fwrite(data.bytes,1,data.length,stdout)==data.length?0:1;
}}
