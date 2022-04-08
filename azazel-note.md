检测实现代码地址：[__https://github.com/haozhuoD/detect-azazel/__](https://github.com/haozhuoD/detect-azazel/)

# 安装 azazel

环境: ubuntu20.04

```text
sudo apt-get install python      # 安装python
sudo apt-get install libpam0g-dev  # 安装pam库
sudo apt-get install libssh-dev     #安装ssh库
sudo apt-get install libpcap-dev
```

## Makefile

这是将编译好的.so文件加载 azazel 自己的动态链接库的Makefile

```text
INSTALL=/lib
install: all
    @echo [-] Initiating Installation Directory $(INSTALL)
    # 打印
    @test -d $(INSTALL) || mkdir $(INSTALL)
    # -d 参数：测试INSTALL是否未一个目录 如果不是目录那么我们就创建一个目录
    @echo [-] Installing azazel 
    # 打印
    @install -m 0755 libselinux.so $(INSTALL)/
    # 修改目录权限为 0755（用户具有读/写/执行权限，组用户和其它用户具有读写权限）
    # 并 将libselinux.so拷贝到INSTALL目录 
    @echo [-] Injecting azazel
    # 注入.so 到 预加载so  文件preload方式
    @echo $(INSTALL)/libselinux.so > /etc/ld.so.preload
```



## azazel攻击复现：

反调试：

基于ptrace的strace、ldd：（lsof、ps）

![](https://tcs-devops.aliyuncs.com/storage/112d1cd776797b8822f4de896b7f4db5ce5f?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQxY2Q3NzY3OTdiODgyMmY0ZGU4OTZiN2Y0ZGI1Y2U1ZiJ9._He8BWoS3Gie5TXxMzM28Dgn47uRNGxHfUvcouttkSM&download=image.png "")



隐藏文件和目录：

![](https://tcs-devops.aliyuncs.com/storage/112d5b9d1ab124c361a91069639af2858dbe?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQ1YjlkMWFiMTI0YzM2MWE5MTA2OTYzOWFmMjg1OGRiZSJ9.DDn8gzxqENL7qidsBFrBhd6xREeZetIiiJ7RJhTraKY&download=image.png "")

默认隐藏包含__的文件和目录，所以会导致重启时找不到部分文件造成不可逆的损害。

![](https://tcs-devops.aliyuncs.com/storage/112d5dc5ed27b15f3f87d86e6c494950ca6c?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQ1ZGM1ZWQyN2IxNWYzZjg3ZDg2ZTZjNDk0OTUwY2E2YyJ9.IaT7kyO3Lzcarcka65IscKviIB3dy9z79gGGeqbyxc8&download=image.png "")



隐藏远程连接：

隐藏登录：                尝试使用  ssh  连接 

两个accept后门：跟踪打印accept()的调用信息， 发现使用ncat基于tcp反弹的一个shell并没有调用accept( ) ，所以并没有调用azazel.c里的 drop_she**ll() ，所以并没有pty产生  。**

本地和远程的PAM后门：



隐藏进程： 基于readdir64、readdir  实现  

`is_invisible()`函数通过读取 /proc/PID/environ 读取环境变量，当存在环境变量

```shell
cat /proc/1657/environ | tr '\0' '\n' | grep ***  //查看环境变量    
export HIDE_THIS_SHELL=666  //设置临时环境变量
unset HIDE_THIS_SHELL        // 取消环境变量设置
```

在运行想要隐藏的进程之前，设置环境变量 HIDE_THIS_SHELL = 任意值 ，即可隐藏进程

![](https://tcs-devops.aliyuncs.com/storage/112e4ec4c23950910d935bc8a372618ce958?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmU0ZWM0YzIzOTUwOTEwZDkzNWJjOGEzNzI2MThjZTk1OCJ9.wAmOPp0KQ3cLt4OiY55CPU5U8D5fGmEUyIvGhP5zThA&download=image.png "")





基于 pty 的 utmp/wtmp 条目的日志清理：

/var/run/utmp：记录当前正在登录系统的用户信息，默认由who和w记录当前登录用户的信息，uptime记录系统启动时间；

/var/log/wtmp：记录当前正在登录和历史登录系统的用户信息



last默认读取 /var/log/wtmp

last -f /var/run/utmp



无法使用gcc进行编译：

![](https://tcs-devops.aliyuncs.com/storage/112d2efaaa36f723e5806fd720c9294beab1?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQyZWZhYWEzNmY3MjNlNTgwNmZkNzIwYzkyOTRiZWFiMSJ9.whUOmOU465qeUc3nJ4G4-CA7fvb0fpzuDy82ML8jlWQ&download=image.png "")



## azazel感染的后果:

- gdb无法使用 (因为ptrace被hook了，GDB是基于ptrace的)

- `bits/types/__sigset_t.h`无法找到

- 每一个之后的运行程序都被注入了对应的.so库

- 魔改某一对应函数





## 卸载azazel

清除方式： 先删除libaselinux.so 再删除ld.so.perload内容

（可能需要到 /lib/ 目录下进行rm）

```text
rm -rf /lib/libaselinux.so
sudo rm -rf /etc/ld.so.preload
```

先删除libaselinux.so（/lib/libaselinux.so）

![](https://tcs-devops.aliyuncs.com/storage/112dd5bcedfd5bc9b667b6569668b5152f08?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmRkNWJjZWRmZDViYzliNjY3YjY1Njk2NjhiNTE1MmYwOCJ9.Xz25OuzpkBqUbiMDXWf1kwAi3CbAEHNIoDh0cYdFIV8&download=image.png "")

## 查看azazel的各种参数 

azazel目录下- 查看：const.h  修改：config.py



# azazel源码分析：

这是一个 azazel 隐藏文件目录的简单分析：https://www.wenwenya.com/anquan/560104.html

主要分为3大模块：azazel.c 、crypthook.c、pam.c 、pcap.c   

### azazel.c  

（hook 24 个系统调用函数+简单粗暴的截断ptrace）

大部分是遵循简单的三个步骤（仅accept比较特别）

![](https://tcs-devops.aliyuncs.com/storage/112de7d3539f6f2edc51432c6d04088fe05d?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmRlN2QzNTM5ZjZmMmVkYzUxNDMyYzZkMDQwODhmZTA1ZCJ9.mUlixZRgwFfAh_dzSjg1gUPz0iGAwbnSI63sYyZ3cSU&download=image.png "")

`is_owner`： 记录hook 的24个系统调用函数到syscall_list中（仅在最开始时执行一次），删除部分日志（注入后会删除一些日志文件，会对系统造成损害），判断当前是否为azazel的内部调用`is_invisible`：判断路径是否可见（实现隐藏）

简单三个步骤：

第一步： 判断是否为azazel的内部调用，若是，则直接返回正确的函数

第二步：判断路径是否可见，若不可见，则直接反回路径不存在，或加工参数后返回

第三步：返回正确的系统调用函数

总的来说都是先通过对输入的参数进行解析，可修改参数或截断调用直接返回。



### crypthook.c     

（提供与read、write相对应的crypt加密读写接口，）	

 hook crypt加密函数，在返回程序前先解密（crypt_write） ， 发送前先加密（crypt_read）



### pam.c 

Linux-PAM(linux可插入认证模块)是一套共享库,使本地系统管理员可以随意选择程序的认证方式

hook 函数（通过调用时的参数判断后，截断调用返回）：

		pam_authenticate                    // 留下rootme用户通信证

		pam_sm_authenticate			

		pam_open_session   	

		getpwnam		： 查询密码文件指定账号rootme时 返回root

		getpwnam_r     ：同上

		pam_acct_mgmt    ：留下rootme后门，直接PAM_SUCCESS



### pcap.c   

 ( hook pcap_loop 函数)

	网络数据包捕获函数库

		pcap_loop 函数第一个参数是函数pcap_open_live返回的指针，第二个参数是需要抓的数据包的个数，一旦抓到了cnt个数据包，pcap_loop立即返回。负数的cnt表示pcap_loop永远循环抓包，直到出现错误；第三个参数是一个回调函数指针

		主要更换第三个参数，隐藏相应端口的浏览

```text
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
--> drop_shell(sock, addr) 
    -->check_shell_password(sock, crypt_mode)
    -->openpty(&pty, &tty, pty_name, NULL, NULL)
    -->子进程 setup_pty(sock, &pty, &tty)
    -->子进程 shell_loop(sock, pty, crypt_mode)
​
```

```text
int openpty(int *amaster, int *aslave, char *name,
            const struct termios *termp,
            const struct winsize *winp);            
```

**openpty**()函数查找可用的伪终端，并以amaster和aslave的形式返回主服务器和从服务器的文件描述符。如果name不为NULL，则以name返回从站的文件名。如果termp不为NULL，则从站的终端参数将设置为termp中的值。如果winp不为NULL，则从站的窗口大小将设置为winp中的值。



		综上，azazel实现的基本逻辑都是相同的，对于想要劫持的函数，通过其函数参数判断是否需要额外处理。若无需处理直接调用原函数再返回。若需要处理，分为两种情况：1、将处理后的参数传到原函数并返回；2、直接让其返回失败或NULL。

		因为azazel本身就是反ptrace调试（hook了ptrace函数），所有基ptrace的strace和GDB还有ldd都将在注入之后不起作用。



## 学习并使用bpftrace观测azazel函数调用特征

bpftrace Install：

[bpftrace/INSTALL.md at master · iovisor/bpftrace (github.com)](https://github.com/iovisor/bpftrace/blob/master/INSTALL.md#ubuntu-packages)

（推荐采用源码下载，支持循环等更多特性）

Ubuntu20.04

```text
sudo apt-get install -y bpftrace
```

一行bpftrace小练习：

[bpftrace/tutorial_one_liners_chinese.md at master · iovisor/bpftrace (github.com)](https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners_chinese.md)



# uprobe 用户态的观测   ---------未实现

思路1：先用bpftrace观测一下 /lib/x86_64-linux-gnu/libc.so.6 ：*  中一些函数的调用逻辑，相应得出思路，找到突破口。（对比正常的动态lib库找找思路）

尝试：单独观察ptrace  uprobe:/lib/x86_64-linux-gnu/libc.so.6:ptrace 并没有办法得到有效信息(比如函数调用序列、动态库的查找序列都比较难得到)   -- 但能得到出调用此函数的一些基本信息。

	写一个简单测试程序通过追踪这个进程可以观察到它的动态函数库函数的调用序列，但是想要从这方面进行检测还是比较困难，因为检测是需要对比或者是得到恶意程序的函数调用或者动态库加载信息，进行分析。

	但是如果像这样在用户态想使用 uprobe 观察用户态的函数或者进程函数调用，在一定的隐藏策略下想要找到我们想追踪的恶意进程可能还是可以实现的，但是对于azazel这种动态函数库的劫持，在这个azazel注入后恶意.so的路径和具体被劫持的函数 我们是不可知的，而uprobe想要动态观测当前用户态的函数必须指明其函数名和函数所在文件的路径。

        我们现在可以给出重要的、想要检测的函数名，但我们还是无法知道azazel注入的.so文件的路径，所以目前还是没有办法实现。

       所以目前想到只能通过观察正确动态库中正确函数的行为，但是这是很困难的，azazel并不是完全截断调用正确动态库中的正确函数，其hook的函数调用存在正常调用、截断、修改参数调用三种情况，感觉很难从检测正确函数的角度进行检测。

-------------   比较困难（uprobe 监听主要是难在不知道具体的监听目标  -- 仍然未解决

        

        uprobe\uretprobe 提供 uaddr,usym 函数 。 bpftrace运行uprobe探针时需指定检测文件的具体路径 , 进行检测时无法确定被注入动态库(*.so)文件的路径，所以仍难以使用bpftrace检测动态库注入。





# 检测方法1：观测所有的系统调用，通过pid这些进行隔离分类

实现代码 ：https://github.com/haozhuoD/detect-aazel/blob/master/traceall/trace_syscall.c

如何解决系统调用序列太多，该如何从中找出有价值的序列 

思考：

azazel造成一个进程的系统调用序列不同的两种情况：

1、截断用户态的系统调用请求，直接返回特定的结果。

2、修改系统调用请求的部分参数后，再调用系统调用运行。

如何检测出这些不同（如何推断出这个系统调用序列是有问题的）

  ------(问题其实就大致约等于使用strace检测动态注入)

——>通过这个检测不同我们能找到哪些进程是可能存在被注入的风险。



根据这个优先加载查找动态库的特性，其实我们只跟踪有关文件操作的系统调用

openat、access、execve、stat、statfs等

tracepoint:syscalls:sys_enter_{ statfs、fstatfs、ustat 、open、openat、openat2、execve、execveat、access、faccessat、faccessat2}

access访问返回 值不为负数（-1），则表示存在被优先加载劫持的风险。

（动态加载优先级的机制决定了会先access尝试访问/etc/ld.so.preload）

实现使用strace检测动态注入:

![](https://tcs-devops.aliyuncs.com/storage/112d747ea67925d1be49134d6edbca029543?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQ3NDdlYTY3OTI1ZDFiZTQ5MTM0ZDZlZGJjYTAyOTU0MyJ9.-1dNVyx_NIi0RJfA_cG-RAHGsrFKLDmh2VZ7a90wZ3s&download=image.png "")

![](https://tcs-devops.aliyuncs.com/storage/112dc2baf96d9727d1cc638cd4a6ca74ca6d?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmRjMmJhZjk2ZDk3MjdkMWNjNjM4Y2Q0YTZjYTc0Y2E2ZCJ9.HkApJ1AVimWkC9A6Qa_BYBTxALeKWRDsrZtpciSfYus&download=image.png "")

根据这个思路，使用Bpftrace跟踪有关文件操作的系统调用也是可以实现检测动态注入的

基于 `access返回 值不为负数（-1），则表示存在被优先加载劫持的风险`    这句话进行的检测。

根据尝试，只需要tracepoint:syscalls:sys***openat与sys_exit_access，即可实现检测。并给出可能存在优先加载的库函数

![](https://tcs-devops.aliyuncs.com/storage/112d29dd0425820cdb0d82082c7214b81da3?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQyOWRkMDQyNTgyMGNkYjBkODIwODJjNzIxNGI4MWRhMyJ9.Dgl1Bb1xChoHxVmHg_RezcVvub08xX2uQxEL5ueV260&download=image.png "")





# 检测方法2

检测实现代码：[__https://github.com/haozhuoD/detect-aazel/blob/master/compare_so_fun/com_funaddr.c__](https://github.com/haozhuoD/detect-aazel/blob/master/compare_so_fun/com_funaddr.c)

想法2 ：保护/恢复ptrace

保护/恢复ptrace实现代码： [__https://github.com/haozhuoD/detect-aazel/tree/master/protect_ptrace__](https://github.com/haozhuoD/detect-aazel/tree/master/protect_ptrace)

想办法保护ptrace不被劫持，这样就能继续使用基于ptrace的工具进行调试

找到正确的ptrace，实现一个简单的只包含ptrace的*.so动态库，修改 LD_PRELOAD 将它的优先级提到最高

```text
#include <sys/types.h>
#include<dlfcn.h>//Linux动态库的显式调用
/* ----------------------------------------------------------------------- */
    void *handle;//定义句柄指针变量
    //定义函数指针变量
    long (*real_ptrace)(enum __ptrace_request request, pid_t pid);
    //获取包含'ptrace'的库的句柄
    handle = dlopen ("/lib/x86_64-linux-gnu/libc.so.6", RTLD_LAZY);
    //对动态解析函数“ptrace”的引用,go变量存的是ptrace的地址
    real_ptrace = dlsym(handle, "ptrace");
```

编译

```text
gcc -Wall -shared -fpic -o pre_ptrace.so pre_ptrace.c -ldl
```

LD_PRELOAD下使用调试工具

```text
LD_PRELOAD=./*.so gdb **
​
LD_PRELOAD=./pre_ptrace.so strace bin/ls
```

实现如图：（成功在LD_PRELOAD下使用基于ptrace的

![](https://tcs-devops.aliyuncs.com/storage/112d45def6161f7dba36d91a4f8792ea1c27?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQ0NWRlZjYxNjFmN2RiYTM2ZDkxYTRmODc5MmVhMWMyNyJ9.bGfR46hi3UknB_IYLWAlNh6c3e84GiTN71qvo5rzGL8&download=image.png "")



方法2：基于想法2检测 （在dlsym不被劫持的前提下 

我们需要一个可以信任的动态连接库 /lib/x86_64-linux-gnu/libc.so.6，

使用 dlsym 从中找到我们想要对比的函数

在通过 dlsym  的 RTLD_NEXT 参数得到当前系统中的相应函数

对比函数地址，若不一样则相应函数已经被preload 了

		无法使用 uaddr（只能查找在编译时候确定的符号，不能动态使用）

![](https://tcs-devops.aliyuncs.com/storage/112d84a6e85090299f9e09b945057124c70f?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQ4NGE2ZTg1MDkwMjk5ZjllMDliOTQ1MDU3MTI0YzcwZiJ9.CWMaLaWZ2gSCJTOn6LnokXHdW4pF3LSM6bkszB_HPO8&download=image.png "")

![](https://tcs-devops.aliyuncs.com/storage/112d1f6626be6c846a29a3aa1eec1946b24d?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQxZjY2MjZiZTZjODQ2YTI5YTNhYTFlZWMxOTQ2YjI0ZCJ9.3trSwLfDH5G9RUntF16n8hBjkj62zReAk8P0S5Ut5rA&download=image.png "")

实现：	

主要使用：dlinfo 、dlopen、dlsym、dladdr 四个函数

dl相关函数可参考：[https://www.onitroad.com/jc/linux/man-pages/linux/man3/dlinfo.3.html](https://www.onitroad.com/jc/linux/man-pages/linux/man3/dlinfo.3.html)

```text
# 编译
gcc com_funaddr.c -ldl -o detect_ComFunAddr
# 运行
./detect_ComFunAddr 
```

	检测结果如下：

![](https://tcs-devops.aliyuncs.com/storage/112df8a8ed43249c2e5aa814ffac506eee7d?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmRmOGE4ZWQ0MzI0OWMyZTVhYTgxNGZmYWM1MDZlZWU3ZCJ9.IPIKI5VWRmLwYuSyY1ciTMQJuMmL34tIbeixmVMUa-0&download=image.png "")

将azazel里的这些被劫持的函数都检测出来了，同时也指出了这些可能被注入的函数目前所属的动态库 /lib/libselinux.so (就是azazel注入的动态库)

![](https://tcs-devops.aliyuncs.com/storage/112d2fe76b0562dc8865330cb148854417f1?Signature=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBcHBJRCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9hcHBJZCI6IjVlNzQ4MmQ2MjE1MjJiZDVjN2Y5YjMzNSIsIl9vcmdhbml6YXRpb25JZCI6IiIsImV4cCI6MTY1MDAzMTA3MCwiaWF0IjoxNjQ5NDI2MjcwLCJyZXNvdXJjZSI6Ii9zdG9yYWdlLzExMmQyZmU3NmIwNTYyZGM4ODY1MzMwY2IxNDg4NTQ0MTdmMSJ9.cySu-bsRwyl04UkA1zBkvkEblq6-eSQgm0eXfWzxRVA&download=image.png "")

---- 检测成功





