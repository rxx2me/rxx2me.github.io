import os
from Crypto.Util.number import bytes_to_long, getPrime
from random import getrandbits
from sympy import nextprime
m = os.urandom(70)+b"FlagY{Fake_Flag}"+os.urandom(70)
m = bytes_to_long(m)
e = 0x10001
p = getPrime(1024)
q = nextprime(p+getrandbits(512))
n = p*q
ct = pow(m,e,n)

print(f"{n = }")
print(f"{ct = }")

