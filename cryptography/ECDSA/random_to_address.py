#Generate private key for randam number
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
print(private_key)
print(decoded_private_key)