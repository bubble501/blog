#import necessary
import random

#Make greatest common divisor
#Use euclidean algorithm
def gcd(a, b):
    while b != 0:
        a, b = b, a%b
    return a

#Make least common multiple
def lcm(x, y):
    return x * y // gcd(x, y)

#Use extended euclidean algorithm
def gcd2(x, y):
    c0, c1 = x, y
    a0, a1 = 1, 0
    b0, b1 = 0, 1
    
    while c1 != 0:
        m = c0 % c1
        q = c0 // c1
        
        c0, c1 = c1, m
        a0, a1 = a1, (a0 - q * a1)
        b0, b1 = b1, (b0 - q * b1)
        
    return c0, a0, b0

#Parameters
p,q = 50231, 89959
n = p * q
l = lcm(p -1, q - 1)

e = False
while not gcd(e, l) == 1:
    e = random.randint(1,l)
    
c, a, b = gcd2(e, l)
d = a % l
m = 20090103

#Encryption
c = pow(m, e, n)

#Decryption
decryption = pow(c, d, n)

#True / Fail
print(decryption == m)