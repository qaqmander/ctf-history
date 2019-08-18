#!/usr/bin/env python2

from pwn import *
from libnum import *
context.log_level = 'debug'

if args.REMOTE:
    p = remote('47.111.59.243', 9421)
    p.recvuntil('md5(str + ')
    salt = p.recv(4)
    p.recvuntil('== ')
    res = p.recv(5)
    q = process(['./a.out', salt, res])
    good = q.recvline().strip()[:-4]
    q.close()
    print good
    from hashlib import md5
    print md5(good + salt).hexdigest()[:5]
    p.sendline(good)
else:
    p = process('./local.py')

'''
from Crypto.PublicKey import RSA
from Crypto.Random import random

kk = RSA.generate(1024)
m = random.randint(0, kk.n-1)

n = kk.n
e = kk.e
c = kk.encrypt(m, 0)[0]

if True:
    k = 0
    b = 0
    while True:
        print k
        if pow(2, k) >= n:
            m_ = (b + 1) * n / pow(2, k)
            print m
            print m_
            print m == m_
            exit(0)
        k += 1
        #print c
        c0 = pow(2, e * k, n) * c % n 
        temp = kk.decrypt(c0)
        if temp & 1 == 0:
            b = 2 * b
        else:
            b = 2 * b + 1

exit(0)
'''

context.log_level = 'info'
for i in range(3):
    p.recvuntil('n = ')
    n = int(p.recvline().strip())
    p.recvuntil('e = ')
    e = int(p.recvline().strip())

    #p.recvuntil('m = ')
    #m = int(p.recvline().strip())

    p.recvuntil('c = ')
    c = int(p.recvline().strip())
    k = 0
    b = 0
    print i
    while True:
        if k % 100 == 0:
            print k
        if pow(2, k) >= n:
            m = (b + 1) * n / pow(2, k)
            p.sendlineafter('Please input your option:', 'G')
            p.sendlineafter('The secret:', str(m))
            break
        p.sendlineafter('Please input your option:', 'D')
        k += 1
        c0 = pow(2, e * k, n) * c % n 
        p.sendlineafter('Your encrypted message:', str(c0))
        #p.recvline()
        ret = p.recvline()
        if 'even' in ret:
            b = 2 * b
        elif 'odd' in ret:
            b = 2 * b + 1
        else:
            exit(0)
        #if k < 100:
        #    print b, pow(2,k)*m/n, (b + 1)
            
p.interactive()
