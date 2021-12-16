#!/usr/bin/env bpftrace

BEGIN
{
	printf("trace syscalls to detect dynamic injection ...... Hit Ctrl-C to end.\n");

    // printf(" pid    comm               probe-----sys_retval \n");
    // @syscount[4294967296];  //max_pid
    @preload = "/etc/ld.so.preload";
    @ldsocache = "/etc/ld.so.cache";
    @flag = 0;
    // @count = 0;
}

// tracepoint:syscalls:sys_enter_*
// {
// 	@piddata[pid,@syscount[pid]] = pid;      //
//     @commdata[pid,@syscount[pid]] = comm;    //进程名
//     @probedata[pid,@syscount[pid]] = probe;  //探针名
//     	// printf("%-6d  %-16s  %s\n", pid, comm, probe);
//     @syscount[pid] = @syscount[pid]+1;
    
// }

// -----------------------------------------------------------------------------------------
tracepoint:syscalls:sys_enter_access
{
    // if(comm != "bpftrace"){
    //     printf("%-6d  %-16s  %-16s  %-6d   \n", pid, comm, probe,args->ret);
    // }
    @access_filename[pid] = args->filename;
    @access_mode[pid] = args->mode;
    // printf("%-16s sys_enter_access (%s , %d )  = \n", comm,str(args->filename),args->mode);
}

tracepoint:syscalls:sys_exit_access
/@access_filename[pid]/
{
    // if(comm != "bpftrace"){
    //     printf("%-6d  %-16s  %-16s  %-6d   \n", pid, comm, probe,args->ret);
    // }  %s  ,@access_mode[pid]
    // $preload = "/etc/ld.so.preload";18
    // @ldsocache = "/etc/ld.so.cache";16
    // strncmp(char *s1, char *s2, int length)
    // if((str(@access_filename[tid]) == @preload ) && (args->ret >= 0)){
        // printf("==== sys_exit_access === flag = %d strncmp : %d , args->ret: %d \n",@flag,(strncmp(@preload,str(@access_filename[pid]),18)==0),args->ret);
    if( (strncmp(@preload,str(@access_filename[pid]),18)==0) && (args->ret >= 0)){

        printf("...... /etc/ld.so.preload DOES definitely exist.. little warning\n");
        printf("[+] %s's result may wrong !\n",comm);
        @flag = 1;
        // @count = 0;
        // clear(@Inject_so);
    }   
    // printf("%-16s sys_access (%s , umode_t: %d)  = %d\n", comm,str(@access_filename[pid]),@access_mode[pid],args->ret);
}

tracepoint:syscalls:sys_enter_openat
{
    // if(comm != "bpftrace"){
    //     printf("%-6d  %-16s  %-16s  %-6d   \n", pid, comm, probe,args->ret);
    // }
    @openat_filename[pid] = args->filename;
    @openat_mode[pid] = args->mode;
    // printf("%-16s sys_enter_openat (%s , umode_t:%d )  =   \n", comm,str(args->filename),args->mode);
}

tracepoint:syscalls:sys_exit_openat
/@openat_filename[pid]/
{
    // if(comm != "bpftrace"){
    //     printf("%-6d  %-16s  %-16s  %-6d   \n", pid, comm, probe,args->ret);
    // }            %d,@openat_mode[pid]
    // $preload = "/etc/ld.so.preload";
    // $ldsocache = "/etc/ld.so.cache";
    // strncmp(@preload,str(@access_filename[tid]),19)
    // printf("==== sys_exit_openat === flag = %d, strncmp : %d , args->ret: %d \n",@flag,strncmp(@preload,str(@access_filename[pid]),18),args->ret);
    if(@flag && strncmp(@preload,str(@openat_filename[pid]),18) ){
        if( strncmp(@ldsocache,str(@openat_filename[pid]),16) ){
            //循环有问题//不建议在bpftrace里写循环
            // $i = 0;
            // while ($i < 20) {
            //     if($i < @count){
            //         printf(" %s \n",@Inject_so[$i] );
            //     }
            // }
            // for($i = 0;$i < 20;$i++){
            //     if($i < @count){
            //         printf(" %s \n",@Inject_so[$i] );
            //     }
            // }
            
            printf("[+] You may have been dynamically injected !!! \n");
            printf("[+] please check these *.so files  by yourself !!! \n");
            printf("==================================================\n");
            printf("[!]  %s \n",str(@openat_filename[pid]));
            
        }else{
            @flag = 0;
            printf("==================================================\n");
            exit();
            // @Inject_so[@count] = str(@openat_filename[pid]);
            // @count++;
        }    
    }
    
    // printf("%-16s sys_openat (%s , umode_t: %d)  =  %d \n", comm,str(@openat_filename[pid]),@openat_mode[pid],args->ret);
}
END
{
    clear(@openat_filename);
    clear(@access_filename);
    // clear(@execve_filename);
    clear(@openat_mode);
    clear(@access_mode);
    clear(@flag);
    clear(@ldsocache);
    clear(@preload);
}

// tracepoint:syscalls:sys_enter_execve
// {
//     // if(comm != "bpftrace"){
//     //     printf("%-6d  %-16s  %-16s  %-6d   \n", pid, comm, probe,args->ret);
//     // },args->argv,args->envp
//     @execve_filename[pid] = args->filename;
//     // printf("%-16s sys_enter_execve (%s )   =  \n", comm,str(args->filename));
// }
// // // -------------------------------------------------------------------------------------------

// tracepoint:syscalls:sys_exit_execve
// /@openat_filename[pid]/
// {
//     // if(comm != "bpftrace"){
//     //     printf("%-6d  %-16s  %-16s  %-6d   \n", pid, comm, probe,args->ret);
//     // }                ,args->argv,args->envp
//     // printf("%-16s sys_exit_execve (%s )   = %d \n", comm,str(@execve_filename[pid]),args->ret);
// }

// END
// {
// 	// clear(@filename);
//     // $i = 0;
//     // while ($i <= 4294967296) {
//     //     if(@piddata[i,0]){
//     //         $syscount = 0;
//     //         while(!@piddata[i,$syscount]){
//     //             printf("%-6d %-16s %s\n", @piddata[i,@syscount[$syscount]], @commdata[i,@syscount[$syscount]],@probedata[i,@syscount[$syscount]]);
//     //             $syscount++;
//     //         }   
//     //     }
//     //     $i++;
//     // }

//     clear(@openat_filename);
//     clear(@access_filename);
//     clear(@execve_filename);
//     clear(@openat_mode);
//     clear(@access_mode);
//     clear(@flag);
//     clear(@ldsocache);
//     clear(@preload);


// }