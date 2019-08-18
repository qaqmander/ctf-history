from Crypto.Random import random
from Crypto.Util import number

def convert(m):
    m = m ^ m >> 13
    m = m ^ m << 9 & 2029229568
    m = m ^ m << 17 & 2245263360
    m = m ^ m >> 19
    return m

target = '641460a9e3953b1aaa21f3a2'
