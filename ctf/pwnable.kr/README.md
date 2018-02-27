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
scp -r -P 2222 fd@pwnable.kr:/home/fd/fd.c ./
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

### rank2 - collision
拿到这个题目后，看了下源码:
``` c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```
关键位置在于`if(hashcode == check_passwoed(argv[1])`这一行，如果二者相等，那么就通过，给出flag，否则退出。

最开始我想到用爆破的方式，就是使用gdb调试程序，动态的将此处的`jne`改成`je`但是发现这样不会执行`system("/bin/cat flag"`,说权限不够。应该是调试状态设置了权限不让运行，于是只有分析算法，让程序自己运行到这个位置希望能够成功，注意`check_password`函数
``` c
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}
```
函数的参数为一个字符串，这里为程序的第一个参数`argv[1]`, 长度为20字节，首先程序将这个字符串转换为`int`数组，int为4字节，自然20字节的字符串变为5个整数，然后将这5个整数相加，最后返回结果。返回的结果只要等于`hashcode`，就进入打印flag的部分，这里hashcode已经给出`hashcode = 0x21DD09EC`,所以需要构造合适的字符串转化为整数数组加起来的值为`0x21DD09EC`即可。

``` python
>>> hashcode = 0x21DD09EC
>>> x = 0x02020202
>>> y = hashcode - 4*x
>>> print hex(x)
0x2020202
>>> print hex(y)
0x19d501e4
>>> str = '\xe4\x01\xd5\x19' + 4*4*'\x02'
>>> print len(str)
20
>>> str
'\xe4\x01\xd5\x19\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02'
>>>
```
注意大端模式，`0x19d501e4`在内存中的排列顺序应为`e401d519`

然后运行得到flag，这里利用pwntool这个工具将输入传入到stdin：
``` python
>>> from pwn import *
>>> io  = process(['./col', str])
[x] Starting local process './col'
[+] Starting local process './col': Done
>>> io.recvline()
[*] Process './col' stopped with exit code 0
'daddy! I just managed to create a hash collision :)\n'
```

flag is `daddy! I just managed to create a hash collision :)`  
