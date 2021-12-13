#!/usr/bin/env bpftrace

BEGIN
{
	printf("trace all syscalls... Hit Ctrl-C to end.\n");

    printf(" pid    comm               probe-----sys_retval \n");
    // @syscount[4294967296];  //max_pid
}

// tracepoint:syscalls:sys_enter_*
// {
// 	@piddata[pid,@syscount[pid]] = pid;      //
//     @commdata[pid,@syscount[pid]] = comm;    //进程名
//     @probedata[pid,@syscount[pid]] = probe;  //探针名
//     	// printf("%-6d  %-16s  %s\n", pid, comm, probe);
//     @syscount[pid] = @syscount[pid]+1;
    
// }

tracepoint:syscalls:sys_exit_*
{
    if(comm != "bpftrace"){
        printf("%-6d  %-16s  %-16s  %-6d   \n", pid, comm, probe,args->ret);
    }
	
}

END
{
	// clear(@filename);
    // $i = 0;
    // while ($i <= 4294967296) {
    //     if(@piddata[i,0]){
    //         $syscount = 0;
    //         while(!@piddata[i,$syscount]){
    //             printf("%-6d %-16s %s\n", @piddata[i,@syscount[$syscount]], @commdata[i,@syscount[$syscount]],@probedata[i,@syscount[$syscount]]);
    //             $syscount++;
    //         }   
    //     }
    //     $i++;
    // }
}