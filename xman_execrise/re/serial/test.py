#!/usr/bin/env python
ls = [0x45, 0x5a, 0x39, 0x64, 0x6d, 0x71, 0x34, 0x63] + [0] * 8
t = [0x9b, 0x9b, 0x9b, 0x9b, 0xb4, 0xaa, 0x9b, 0x9b]

i = 0
j = 0
k = 15
for _ in range(8):
    ls[k] = t[j] - ls[i]
    i += 1
    j += 1
    k -= 1
print ''.join(map(chr, ls))

