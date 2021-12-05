#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>

int main(int argc, char **argv){
    int pid = getpid();
    printf("pid = %d\n", pid);
    FILE *fp = fopen("a.txt", "w");
    fprintf(fp, "hello world!\n");
    fclose(fp);
    exit(0);
}