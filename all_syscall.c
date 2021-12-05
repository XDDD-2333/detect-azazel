
uprobe:/home/dhz/detect/mytest:main
{
    @pid = pid;
}

tracepoint:syscalls:sys_enter_*
/pid == @pid/
{
    printf("%s\n", probe);
}
