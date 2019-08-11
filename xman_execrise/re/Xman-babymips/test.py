t1 = 'Q|j{g'
t2 = [0x52, 0xFD, 0x16, 0xA4, 0x89, 0xBD, 0x92, 0x80, 0x13,
      0x41, 0x54, 0xA0, 0x8D, 0x45, 0x18, 0x81, 0xDE, 0xFC,
      0x95, 0xF0, 0x16, 0x79, 0x1A, 0x15, 0x5B, 0x75, 0x1F]

t = list(map(ord, t1)) + t2

def func(i, v):
    v ^= 0x20 - i
    if 5 <= i < len(t):
        if i & 1 == 0:
            v = (v << 2) | (v >> 6)
        else:
            v = (v >> 2) | (v << 6)
    v &= 0xff
    return v

ans = []

print(func(31, 125))

for i in range(0x20):
    for j in range(0x100):
        if func(i, j) == t[i]:
            ans.append(j)
            #break

print(ans)
print(''.join(map(chr, ans)))
