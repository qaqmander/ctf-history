#!/usr/bin/env python

from pwn import *

ls = [-1] * 42
ls[0] = 123
a = '53fc275d81'
for i in range(len(a)):
    ls[i+1] = ord(a[i])
ls[len(ls) - 1] = 125
a = '4938ae4efd'
for i in range(len(a)):
    ls[i+31] = ord(a[i])
print ls
target = '{daf29f59034938ae4efd53fc275d81053ed5be8c}'
target = map(ord, target)
print target
temp = target[:1] + target[21:41] + target[1:21] + target[41:]
print temp
print ''.join(map(chr, temp))
