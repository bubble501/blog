import hashlib
from binascii import hexlify, unhexlify
import sys
from account import *
from Crypto.Cipher import AES
import pylibscrypt as scrypt
from priv_to_addr import *
from base58 import b58encode

def _encrypt_xor(a, b, aes):
    a = unhexlify('%0.32x' % (int((a), 16) ^ int(hexlify(b), 16)))
    return aes.encrypt(a)

def encrypt(privkeyhex, addr, passphrase):
    a = bytes(addr, 'ascii')
    salt = hashlib.sha256(hashlib.sha256(a).digest()).digest()[0:4]
    key = scrypt.scrypt(bytes(passphrase, "utf-8"), salt, 16384, 8, 8)
    derived_half1, derived_half2 = key[:32], key[32:]
    aes = AES.new(derived_half2)
    encrypted_half1 = _encrypt_xor(privkeyhex[:32], derived_half1[:16], aes)
    encrypted_half2 = _encrypt_xor(privkeyhex[32:], derived_half1[16:], aes)
    payload = (b'\x01' + b'\x42' + b'\xc0' +
               salt + encrypted_half1 + encrypted_half2)
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    privatkey = hexlify(payload + checksum).decode('ascii')
    return Base58(privatkey)

privkey = '5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn'
passphrase = "MyTestPassphrase"
privkeyhex = binascii.b2a_hex(wif_to_private_key(privkey)).decode('utf-8')
addr = privkey_addr(privkey)

encrypted_privkey = format(encrypt(privkeyhex, addr, passphrase), "encwif")
print(encrypted_privkey)

def decrypt(encrypted_privkey, passphrase):
    d = unhexlify(base58decode(encrypted_privkey))
    d = d[2:]   # remove trailing 0x01 and 0x42
    flagbyte = d[0:1]  # get flag byte
    d = d[1:]   # get payload
    salt = d[0:4]
    d = d[4:-4]
    key = scrypt.scrypt(bytes(passphrase, "utf-8"), salt, 16384, 8, 8)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    encryptedhalf1 = d[0:16]
    encryptedhalf2 = d[16:32]
    aes = AES.new(derivedhalf2)
    decryptedhalf2 = aes.decrypt(encryptedhalf2)
    decryptedhalf1 = aes.decrypt(encryptedhalf1)
    privraw = decryptedhalf1 + decryptedhalf2
    privraw = ('%064x' % (int(hexlify(privraw), 16) ^
                          int(hexlify(derivedhalf1), 16)))
    return privraw

private_key = binascii.a2b_hex(decrypt(encrypted_privkey, passphrase))
print(private_key_to_wif(private_key))