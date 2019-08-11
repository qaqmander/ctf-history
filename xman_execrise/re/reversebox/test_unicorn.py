#!/usr/bin/env python

from unicorn import *
from unicorn.x86_const import *
from pwn import *

BASE = 0x8048000
STACK_SIZE = 0x1000 * 4
STACK_ADDR = 0xf8000000 - STACK_SIZE

mu = Uc(UC_ARCH_X86, UC_MODE_32)

OUTPUT_ADDR = 0x1000
mu.mem_map(OUTPUT_ADDR, 0x1000)
mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, 0x1000 * 4)
mu.mem_write(BASE, open('./reverse_box').read())
mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE - 0x8)
mu.reg_write(UC_X86_REG_EBP, STACK_ADDR + STACK_SIZE)
mu.mem_write(STACK_ADDR + STACK_SIZE - 4, p32(OUTPUT_ADDR))

skip_list = [0x0804859A, 0x080485A2]
rand_addr = 0x080485A7

def hook_code(mu, address, size, user_data): 
#print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 
    if address in skip_list:
        mu.reg_write(UC_X86_REG_EIP, address + size)
    if address == rand_addr:
        mu.reg_write(UC_X86_REG_EIP, address + size)
        mu.reg_write(UC_X86_REG_EAX, 0xd6)

mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(0x0804858D, 0x08048688)

a = mu.mem_read(OUTPUT_ADDR, 0x100)
a = list(a)
#print a
target = [149, 238, 175, 149, 239, 148, 35, 73, 153, 88, 47, 114, 47, 73, 47, 114, 177, 154, 122, 175, 114, 230, 231, 118, 181, 122, 238, 114, 47, 231, 122, 181, 173, 154, 174, 177, 86, 114, 150, 118, 174, 122, 35, 109, 153, 177, 223, 74]
ans = []
for i in target:
    ans.append(a.index(i))
print ''.join(map(chr, ans))

#import IPython
#IPython.embed()
