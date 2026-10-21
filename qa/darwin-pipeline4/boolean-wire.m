#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>
#include <stdint.h>

/* Physical Foundation regression for the five logical wire constructors.
 * C comparison/logical expressions are int; the cast must precede boxing.
 * This checks serialization, not the service or its containment capability. */
int main(void) { @autoreleasepool {
    for (int phase=0;phase<2;phase++) {
    volatile bool expected=phase==0;
    volatile bool poisoned=!expected, stopping=false, stopped=expected, valid=true, same=expected, latched=expected;
    volatile uint64_t clock=expected?10:8, deadline=9;
    NSDictionary *value=@{
        @"registry_health_cached":@((bool)!poisoned),
        @"status_stop_latched":@((bool)(stopping||stopped)),
        @"cached_stop_latched":@((bool)(valid&&same&&(stopping||latched))),
        @"timed_out":@((bool)(clock>=deadline)),
        @"run_stop_latched":@((bool)(stopping||stopped))
    };
    for (NSString *key in value) {
        if(CFGetTypeID((__bridge CFTypeRef)value[key])!=CFBooleanGetTypeID())return 1;
    }
    NSNumber *numericControl=@(clock>=deadline);
    if(CFGetTypeID((__bridge CFTypeRef)numericControl)==CFBooleanGetTypeID())return 2;
    NSData *data=[NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
    NSDictionary *roundtrip=data?[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]:nil;
    if(roundtrip.count!=5)return 3;
    for(NSString *key in roundtrip)if(CFGetTypeID((__bridge CFTypeRef)roundtrip[key])!=CFBooleanGetTypeID()
        ||[roundtrip[key] boolValue]!=expected)return 4;
    }
    return 0;
}}
