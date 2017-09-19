import binascii
import hashlib
from base58 import b58encode
from base58 import b58decode
import ecdsa

def wifchecksum(code):                                                                                                
    return hashlib.sha256(hashlib.sha256(code).digest()).digest()[:4]


def wif_to_private_key(wif):
    code = b58decode(wif)
    prefix      = code[0]
    private_key = code[1:33]
    checksum    = code[33:]                  
    if code[0] == 128:
        prefix = b'\x80'
    checksum_from_hex = wifchecksum(prefix + private_key)
    assert(checksum == checksum_from_hex)
    return private_key

def _make_checksum_for_address(data):                                                             
    code = hashlib.sha256(hashlib.sha256(data).digest()).digest()
    return code[:4]

def private_to_public_key(private_key):
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.verifying_key
    return verifying_key.to_string()


def public_key_to_address(public_key):
    pk_with_prefix = b"\x04" + public_key
    ripemd160   = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(pk_with_prefix).digest())
    hash160     = ripemd160.digest()
    vhash160    = b"\x00" + hash160
    
    checksum    = _make_checksum_for_address(vhash160)
    raw_address =vhash160 + checksum
    
    return b58encode(raw_address)

def privkey_addr(wif):
    private_key= wif_to_private_key(wif)
    public_key = private_to_public_key(private_key)
    return(public_key_to_address(public_key))

def private_key_to_wif(private_key):
    assert(len(private_key) == 32)                          
    checksum = wifchecksum(b"\x80" + private_key)      
    return b58encode(b"\x80" + private_key + checksum)