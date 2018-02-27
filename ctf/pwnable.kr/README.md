### [pwnable.kr](http://pwnable.kr)练习记录-WP

### rank1 - fd

use `ssh` connect to server 
``` bash
fd@ubuntu:~$ ls
fd  fd.c  flag
fd@ubuntu:~$
```
总共有三个文件，`flag`文件无法查看，权限不够，`fd.c`为源文件，`fd`为可执行文件，将`fd.c`下载下来
``` bash
ssh -r -P 2222 fd@pwnable.kr:/home/fd/fd.c ./
```
查看`fd.c`的内容：
``` c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```
从代码中可以看到，程序使用read函数读取数据数据，
``` c
len = read(fd, buf, 32);
```
然后比较读入的数据和`LETMEWIN\n`进行比较，如果相同，就把flag读取出来。
而`read`函数的的文件流指针由输入数据获取：
``` c
int fd = atoi( argv[1] ) - 0x1234;
```
当fd为0时，指针为`stdin`,所以保证`fd=0`即可，也就是我们跟的第二个参数被`atoi`转化后数值为`0x1234`即可，由于`0x1234 = 4660`,所以运行下列命令即可获取flag
``` bash
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
fd@ubuntu:~$
```
flag = `mommy! I think I know what a file descriptor is!!`
