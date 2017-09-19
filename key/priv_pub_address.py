#Raw private key
import random
import time
import hashlib
import os

def decode_privkey(priv):   
    result = 0
    string = priv
    while len(string) > 0:
        result *= int(16)
        code_strings =  '0123456789abcdef'
        result += code_strings.find(string[0])
        string = string[1:]
    return result

def random_key():   
    entropy = str(os.urandom(32))+ str(random.randrange(2**256)) + str(int(time.time() * 1000000))
    binary_data = entropy if isinstance(entropy, bytes) else bytes(entropy, 'utf-8')
    bin_sha256 = hashlib.sha256(binary_data).digest()
    if isinstance(bin_sha256, str):
        return bin_sha256
    return ''.join('{:02x}'.format(y) for y in bin_sha256)    

N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

valid_private_key = False

while not valid_private_key:
    private_key = random_key()
    decoded_private_key = decode_privkey(private_key)
    valid_private_key = 0 < decoded_private_key < N
print(decoded_private_key)


#Hexadecimal private key for randam number
print(private_key)


#WIF-private key
code_strings = {58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
                256: ''.join([chr(x) for x in range(256)])}

def decode(string, base):   
        base = int(base)
        result = 0
        while len(string) > 0:
            result *= base
            result += string[0]
            string = string[1:]
        return result

def encode(val, base):
    base = int(base)
    code_string = code_strings[base]
    result_bytes = bytes()
    while val > 0:
        curcode = code_string[val % base]
        result_bytes = bytes([ord(curcode)]) + result_bytes
        val //= base
    result_string = ''.join([chr(y) for y in result_bytes])   
    if base == 256:
        result = result_bytes
    else:
        result = result_string
    return result

def bin_to_b58check(inp, magicbyte=0):
    while magicbyte > 0:
        inp = bytes([magicbyte % 256]) + inp
        magicbyte //= 256
    leadingzbytes = 0
    
    for x in inp:
        if x != 0:
            break
        leadingzbytes += 1
    checksum =  hashlib.sha256(hashlib.sha256(inp).digest()).digest()[:4]
    return '1' * leadingzbytes + encode(decode(inp+checksum, 256), 58)

def encode_privkey(priv):
    return bin_to_b58check(encode(priv, 256), 128)

wif_encoded_private_key    = encode_privkey(decoded_private_key)
print(wif_encoded_private_key)


#WIF-compressed privare key
compressed_priv_key = private_key + '01'
wif_compressed_private_key = encode_privkey(decode_privkey(compressed_priv_key))
print(wif_compressed_private_key)


#Hexadecimal public key from private key
P = 2**256 - 2**32 - 977
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)

def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n 

def to_jacobian(p):
    o = (p[0], p[1], 1)
    return o

def jacobian_double(p):
    if not p[1]:
        return (0, 0, 0)
    ysq = (p[1] ** 2) % P
    S = (4 * p[0] * ysq) % P
    M = (3 * p[0] ** 2 + A * p[2] ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p[1] * p[2]) % P
    return (nx, ny, nz)

def jacobian_add(p, q):
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % P
    U2 = (q[0] * p[2] ** 2) % P
    S1 = (p[1] * q[2] ** 3) % P
    S2 = (q[1] * p[2] ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p[2] * q[2]) % P
    return (nx, ny, nz)

def jacobian_multiply(a, n):
    if a[1] == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jacobian_multiply(a, n % N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n//2))
    if (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n//2)), a)   
  
def from_jacobian(p):
    z = inv(p[2], P)
    return ((p[0] * z**2) % P, (p[1] * z**3) % P)    

def fast_multiply(a, n):
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))
public_key = fast_multiply(G, decoded_private_key)

def encode_pubkey(pub):
    return "04" + "%x"%public_key[0] + "%x"%public_key[1] 

hex_encoded_public_key = encode_pubkey(public_key)

print (hex_encoded_public_key)


#Compress public key, adjust prefix depending on whether y is even or odd
(public_key_x, public_key_y) = public_key

if (public_key_y % 2) == 0:
    compressed_prefix = '02'
else:
    compressed_prefix = '03'
    
encode_pubkey =  "%x"%public_key[0]

hex_compressed_public_key = compressed_prefix + encode_pubkey
print (hex_compressed_public_key)


#Generate bitcoin address from public key
import binascii

def decode(string, base):   
        base = int(base)
        result = 0
        while len(string) > 0:
            result *= base
            result += string[0]
            string = string[1:]
        return result
        
def encode(val, base):
        base = int(base)
        code_string = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        result_bytes = bytes()        
        while val > 0:
            curcode = code_string[val % base]
            result_bytes = bytes([ord(curcode)]) + result_bytes
            val //= base
        result_string = ''.join([chr(y) for y in result_bytes])
        return result_string

def bin_to_b58check(inp):
        inp = bytes([0]) + inp
        checksum_prefix = hashlib.sha256(hashlib.sha256(inp).digest()).digest()
        leadingzbytes = 0
        for x in inp:
            if x != 0:
                break
            leadingzbytes += 1
        checksum = checksum_prefix[:4]
        return '1' * leadingzbytes + encode(decode(inp+checksum, 256), 58)
        
    
def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    digest = hashlib.new('ripemd160', intermed).digest()
    return digest

def pubkey_to_address(pubkey):
    return bin_to_b58check(bin_hash160(binascii.unhexlify(pubkey)))

pubkey_to_address(hex_encoded_public_key)


#Generate compressed bitcoin address from compressed public ke
pubkey_to_address(hex_compressed_public_key)