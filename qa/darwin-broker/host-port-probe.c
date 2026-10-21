/* Audit-only: modifies only this process's task special port; no host changes.
 * clang -std=c11 -O2 -Wall -Wextra host-port-probe.c -o host-port-probe
 * sudo ./host-port-probe; actual SDK/runtime availability is the result.
 */
#include <mach/mach.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/task_special_ports.h>
#include <stdio.h>
#include <unistd.h>
static kern_return_t basic(mach_port_t h){
 host_basic_info_data_t info;mach_msg_type_number_t n=HOST_BASIC_INFO_COUNT;
 return host_info(h,HOST_BASIC_INFO,(host_info_t)&info,&n);
}
static kern_return_t privileged_read(mach_port_t h){
 kernel_boot_info_t info;return host_get_boot_info(h,info);
}
int main(void){
 mach_port_t before=mach_host_self(),plain=MACH_PORT_NULL;
 kern_return_t pre_info=basic(before),pre_priv=privileged_read(before);
 kern_return_t get_plain=host_get_special_port(before,HOST_LOCAL_NODE,HOST_PORT,&plain);
 printf("{\"kind\":\"before\",\"euid\":%u,\"basic_rc\":%d,\"privileged_read_rc\":%d,\"get_plain_rc\":%d,\"plain_nonnull\":%s}\n",geteuid(),pre_info,pre_priv,get_plain,MACH_PORT_VALID(plain)?"true":"false");
 if(get_plain!=KERN_SUCCESS||!MACH_PORT_VALID(plain)){
  printf("{\"kind\":\"summary\",\"replacement_observed\":false,\"product_backend_certified\":false}\n");return 0;
 }
 kern_return_t set=task_set_special_port(mach_task_self(),TASK_HOST_PORT,plain);
 mach_port_t after=mach_host_self();kern_return_t post_info=basic(after),post_priv=privileged_read(after),old_priv=privileged_read(before);
 printf("{\"kind\":\"after\",\"set_task_host_rc\":%d,\"basic_rc\":%d,\"privileged_read_rc\":%d,\"old_handle_privileged_read_rc\":%d}\n",set,post_info,post_priv,old_priv);
 printf("{\"kind\":\"summary\",\"replacement_observed\":%s,\"root_positive_control\":%s,\"product_backend_certified\":false}\n",set==KERN_SUCCESS&&post_info==KERN_SUCCESS&&post_priv!=KERN_SUCCESS&&old_priv!=KERN_SUCCESS?"true":"false",pre_priv==KERN_SUCCESS?"true":"false");
 /* This process exits; do not restore a privileged host slot or touch others. */
 return 0;
}
