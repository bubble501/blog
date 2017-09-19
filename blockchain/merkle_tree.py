import hashlib
import re
import binascii

#edian function
def endian(src):
    scr = ''.join(re.split('(..)',src)[1::2][::-1])
    return scr

transaction_hash1 = "e909043fa259d7a36c4e868cb0e4fc2ed589384c1766705d0c4e132117fc207d"
transaction_hash2 = "e6d51744d77bd69a00acc42c322b2aeeec80ee6fcce7bb371fb0239ad2865fd2"

#convert to little endian
transaction_hash1 = endian(transaction_hash1)
transaction_hash2 = endian(transaction_hash2)

#connect to hash1 and hash2
transaction_hash = transaction_hash1 + transaction_hash2

#double hash with SHA256
hash = hashlib.sha256(hashlib.sha256(binascii.a2b_hex(transaction_hash)).digest()).digest()
hash = endian(binascii.b2a_hex(hash).decode('utf-8'))
print(hash)