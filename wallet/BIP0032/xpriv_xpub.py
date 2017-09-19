#master extended private key

#module taken in past articles
from rootseed import *
from decode_encode import *
    
#text
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
print (bip32_masterprivatekey)


#master extended public key

#module taken in past articles
from fast_multiply import *

def bip32_master_public_key(rawtuple):
    dbin = encode(decode(rawtuple, 58), 256, 0)
    
    vbytes = dbin[0:4]
    depth = dbin[4]
    fingerprint = dbin[5:9]
    i = dbin[9:13]
    chaincode = dbin[13:45]
    key = dbin[46:78]+b'\x01'
    newvbytes = b'\x04\x88\xB2\x1E'
     
    pub = fast_multiply(G, decode(key[:32], 256))
    keydata = bytes([2+(pub[1] % 2)]) + encode(pub[0], 256, 32)
    
    bindata = newvbytes + bytes([depth % 256]) + fingerprint + i + chaincode + keydata
    return encode(decode((bindata+hashlib.sha256(hashlib.sha256(bindata).digest()).digest()[:4]), 256), 58, 0)

bip32_masterpublickey = bip32_master_public_key(bip32_masterprivatekey)
print (bip32_masterpublickey)


#address
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
    dbin = encode(decode(pubkey, 58), 256, 0)
    key = dbin[45:78]
    return bin_to_b58check(bin_hash160(key))

bip32_address = pubkey_to_address(bip32_masterpublickey)

print(bip32_address)