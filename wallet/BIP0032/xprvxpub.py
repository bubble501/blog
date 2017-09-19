from rootseed import *
from decode_encode import *
from fast_multiply import *


privatekey = rootseed()
def bip32_master_key(seed):
    I = hmac.new(bytes("Bitcoin seed", 'utf-8'), seed, hashlib.sha512).digest() 
    vbytes = b'\x04\x88\xAD\xE4'
    depth = 0
    fingerprint = b'\x00\x00\x00\x00'
    i = b'\x00\x00\x00\x00'
    chaincode = encode(decode(I[32:], 256), 256, 32)
    keydata = b'\x00'+(I[:32]+b'\x01')[:-1]
    bindata = vbytes + bytes([depth % 256]) + fingerprint + i + chaincode + keydata
    string=bindata+hashlib.sha256(hashlib.sha256(bindata).digest()).digest()[:4]
    return encode(decode(string, 256), 58, 0)

bip32_masterprivatekey = bip32_master_key(privatekey)


def bip32_serialize(rawtuple):
    dbin = encode(decode(rawtuple, 58), 256, 0)
    vbytes = dbin[0:4]
    depth = dbin[4]
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13], 256)
    chaincode = dbin[13:45]
    key = dbin[46:78]+b'\x01'
    newvbytes = b'\x04\x88\xB2\x1E'
    
    privkey = decode(key[:32], 256)
    pub = fast_multiply(G, privkey)
    keydata = bytes([2+(pub[1] % 2)]) + encode(pub[0], 256, 32)
    i = encode(i, 256, 4)
    chaincode = encode(decode(chaincode, 256), 256, 32)
    bindata = newvbytes + bytes([depth % 256]) + fingerprint + i + chaincode + keydata
    return encode(decode((bindata+hashlib.sha256(hashlib.sha256(bindata).digest()).digest()[:4]), 256), 58, 0)

bip32_masterpublickey = bip32_serialize(bip32_masterprivatekey)