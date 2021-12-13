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


////////////////////////////////////////////////////////////////////////////////
