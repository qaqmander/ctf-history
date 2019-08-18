#!/usr/bin/env python2

from pwn import *
from libnum import *
#context.log_level = 'debug'

p = remote('47.111.59.243', 8003)
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

sleep(1)
c, n = [], []
for i in range(4):
    p.recvuntil('= ')
    ret = p.recvuntil('L', drop=True)
    c.append(int(ret, 16))
    p.recvuntil('= ')
    ret = p.recvuntil('L', drop=True)
    n.append(int(ret, 16))
pr = []
for i in range(4):
    pr.append([])
    for j in range(4):
        if j != i:
            pr[i].append(gcd(n[i], n[j]))
    pr[i].append(n[i]/pr[i][0]/pr[i][1]/pr[i][2])
fai = []
for i in range(4):
    fai.append(1)
    for j in range(4):
        fai[i] *= pr[i][j] - 1
d = []
for i in range(4):
    d.append(invmod(n[i], fai[i]))
m = []
for i in range(4):
    m.append(pow(c[i], d[i], n[i]))
for i in range(4):
    p.recvuntil('=')
    p.sendline(hex(m[i]))
p.interactive()
