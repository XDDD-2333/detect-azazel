// tracepoint:syscalls:sys_enter_ptrace
//     int __syscall_nr;
//     long request;
//     long pid;
//     unsigned long addr;
//     unsigned long data;
#!/usr/bin/env bpftrace
BEGIN
{
    printf("Tracing syscalls... Hit Ctrl-C to end.\n");
    // printf("%-6s %-16s  %-6s  %-6s  \n", "request", "pid", "addr","data");
    printf("%-16s  \n", "pid");

}
///////////////////////////////////////////////////////////////////////////////// 



// --------------------------------------------------- ptrace 
// /lib/x86_64-linux-gnu/libc.so.6
uprobe:/lib/x86_64-linux-gnu/libc.so.6:ptrace
{
    // printf("%-6d %-16ld  %-6ld  %-16ld  %-8ld \n", arg0, arg1, arg2,arg3);
    printf("%d \n",arg1);
    // printf("%d ",arg0);
}
// tracepoint:syscalls:sys_exit_ptrace
// /@filename[tid]/
// {
//     $preload = "/etc/ld.so.preload";
//     $ldsocache = "/etc/ld.so.cache";
//     printf("%-6d %-16s %s\n", pid, comm,
//         str(@filename[tid]));
//     if( str(@filename[tid]) == $preload)
//     {
//         @flag = 1;    
//     }
// //    printf("+++ flag %d \n", @flag);
//     if( (str(@filename[tid]) == $ldsocache) && @flag )
//     {
//         printf("++++++  You may have been dynamically injected !!! \n");
//         printf("++++++  please check *.so from \"/etc/ld.so.preload\" here !!! \n");
//         printf("==========  suggestion ==========\n");
//         printf("you need to delete *.so witch is suspicious \n");
//         printf("and then you can clear LD_PRELOAD and /etc/ld.so.preload \n");
//         printf("============  finish ============\n");
//         delete(@filename[tid]);
//         delete(@flag);
//         exit();
//     }
//     delete(@filename[tid]);
// }



////////////////////////////////////////////////////////////////////////////////
