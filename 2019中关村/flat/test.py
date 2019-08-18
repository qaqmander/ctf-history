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

if __name__ == '__main__':
    #gogogo('b fun_check5\nc')
    bc(0x000000000400FB4)
    s = 'flag{92261263-3828-4644-8122-844105855471}'
    #s = map(ord, 'flag{) + [ord('0')] * 36 + [ord('}')]
    #for i in [13, 18, 23, 28]:
    #    s[i] = ord('-')
    #s = ''.join(map(chr, s))
    p.sla('please input string:', s)
    p.i()
