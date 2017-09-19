import binascii
import sys
import hashlib
from binascii import hexlify, unhexlify
from random import choice
from pbkdf2 import PBKDF2
import hmac
import unicodedata
from bip32utils import BIP32Key
PBKDF2_ROUNDS = 2048

#-----------------------------------------------------------------------------------------------------
#Reading to list of mnemonic code 
class Mnemonic(object):
    def __init__(self, language):
        with open('english.txt', 'r') as f:
            self.wordlist = [w.strip() for w in f.readlines()]
            
#Generate mnemonic from entropy        
    def to_mnemonic(self, data):
        h = hashlib.sha256(data).hexdigest()
        b = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8) + \
            bin(int(h, 16))[2:].zfill(256)[:len(data) * 8 // 32]
        result = []
        
        for i in range(len(b) // 11):
            idx = int(b[i * 11:(i + 1) * 11], 2)
            result.append(self.wordlist[idx])
        result_phrase = ' '.join(result)
        return result_phrase
    
    def normalize_string(self, txt):
        if isinstance(txt, bytes):
            utxt = txt.decode('utf8')
        elif isinstance(txt, str):
            utxt = txt
        else:
            raise TypeError("String value expected")
        return unicodedata.normalize('NFKD', utxt)
    
#Root seed genarated using  mnemonic   
    def to_seed(self, mnemonic, passphrase=''):
        mnemonic = self.normalize_string(mnemonic)
        passphrase = self.normalize_string(passphrase)
        return PBKDF2(mnemonic, u'mnemonic' + passphrase, iterations=PBKDF2_ROUNDS,
                      macmodule=hmac, digestmodule=hashlib.sha512).read(64)  
#-----------------------------------------------------------------------------------------------------

#Convert string to hexadecimal string,and decode utf-8 to unicode.
def b2h(b):
    h = hexlify(b)
    return h.decode('utf8')

#Make input and mnemonic list
def process(data, lst):
    code = mnemo.to_mnemonic(unhexlify(data))
    seed = mnemo.to_seed(code, passphrase='TREZOR')
    seed = b2h(seed)
    print('input    : %s (%d bits)' % (data, len(data) * 4))
    print('mnemonic : %s (%d words)' % (code, len(code.split(' '))))
    print('seed     : %s (%d bits)' % (seed, len(seed) * 4))
    print()
    lst.append((data, code, seed))

if __name__ == '__main__':
    out = {}

# Mnemonic.list_languages():
    for lang in ['english']: 
        mnemo = Mnemonic(lang)
        out[lang] = []
        data = []

# Generate random seeds
    for i in range(3):
        data = ''.join(chr(choice(range(0, 256))) for _ in range(8 * (i % 3 + 2)))
        data = data.encode('latin1')
        process(b2h(data), out[lang])