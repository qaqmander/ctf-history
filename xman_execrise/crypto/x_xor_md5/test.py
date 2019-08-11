#!/usr/bin/env python

from base64 import *
from libnum import *

cipher = open('./xmd5_b86e130087cb2b49cbb3b87a784eac28').read()

key = cipher[80:80+16]
cipher = cipher[:80]

def xor(a, b):
    return chr(ord(a)^ord(b))

print cipher
print key

cipher = map(ord, cipher)
key = map(ord, key)

def check():
    temp = ''
    for i in range(65):
        temp += chr(cipher[i] ^ key[i % len(key)])
    return temp

temp = check()

print temp.__repr__()

rkey = key[:]

for i in range(65):
    k = ord(temp[i])
    if ord('A') <= k <= ord('Z'):
        rkey[i % len(rkey)] = cipher[i] ^ (k + 32)
    elif k == 0:
        rkey[i % len(rkey)] = cipher[i] ^ 0x20

rkey[15] = ord('y')^ord(' ')
#rkey[15] = 0
key = rkey
temp = check()
print temp.__repr__() 
print temp
print ''.join(map(chr, key)).encode('hex')
print temp.replace('*key*', 'that')

