#!/usr/bin/env bpftrace
BEGIN
{
    printf("Tracing syscalls... Hit Ctrl-C to end.\n");
    printf("%-6s %-16s  %s\n", "PID", "COMM", "PATH");
}

// --------------------------------------------------- 无结果
tracepoint:syscalls:sys_enter_link,
tracepoint:syscalls:sys_enter_linkat,
tracepoint:syscalls:sys_enter_symlink,
tracepoint:syscalls:sys_enter_symlinkat
/!@filename[tid]/
{
    @filename[tid] = args->oldname;
}

tracepoint:syscalls:sys_enter_link,
tracepoint:syscalls:sys_enter_linkat,
tracepoint:syscalls:sys_enter_symlink,
tracepoint:syscalls:sys_enter_symlinkat
/@filename[tid]/
{
    $preload = "/etc/ld.so.preload";
    $ldsocache = "/etc/ld.so.cache";
    printf("%-6d %-16s %s\n", pid, comm,
        str(@filename[tid]));
    if( str(@filename[tid]) == $preload)
    {
        @flag = 1;    
    }
    if( (str(@filename[tid]) == $ldsocache) && @flag )
    {
        printf("++++++  You may have been dynamically injected !!! \n");
        printf("++++++  please check *.so from \"/etc/ld.so.preload\" here !!! \n");
        printf("==========  suggestion ==========\n");
        printf("you need to delete *.so witch is suspicious \n");
        printf("and then you can clear LD_PRELOAD and /etc/ld.so.preload \n");
        printf("============  finish ============\n");
        delete(@filename[tid]);
        delete(@flag);
        exit();
    }
    delete(@filename[tid]);
}



////////////////////////////////////////////////////////////////////////////////
END
{
    clear(@filename);
}