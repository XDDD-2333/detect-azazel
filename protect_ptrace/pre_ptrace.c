// #include<sys/ptrace.h>
#include<dlfcn.h>//Linux动态库的显式调用
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/* ----------------------------------------------------------------------- */

long ptrace(void *request, pid_t pid, void *addr, void *data) {
    void *handle;//定义句柄指针变量
	//定义函数指针变量
    long (*real_ptrace)(void *request_, pid_t pid_, void *addr_, void *data_);
    //获取包含'ptrace'的库的句柄
    handle = dlopen ("/lib/x86_64-linux-gnu/libc.so.6", RTLD_LAZY);
    //对动态解析函数“ptrace”的引用,go变量存的是ptrace的地址
    real_ptrace = dlsym(handle, "ptrace");
    return real_ptrace(request, pid, addr, data);
}

	