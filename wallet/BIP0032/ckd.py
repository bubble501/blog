#generate ckd private key
from xprvxpub import *


def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    digest = hashlib.new('ripemd160', intermed).digest()
    return digest

def privkey_to_pubkey(privkey):
    return bytes([2+(fast_multiply(G, decode(privkey[:32], 256))[1] % 2)])\
                                + encode(fast_multiply(G, decode(privkey[:32], 256))[0], 256, 32)
                      
def bip32_ckd_prv(data, i = int(i)):

    dbin = encode(decode(data, 58), 256, 0)
    vbytes = dbin[0:4]
    depth = dbin[4] + 1
    chaincode = dbin[13:45]
    key = dbin[46:78]+b'\x01'
    fingerprint = bin_hash160(privkey_to_pubkey(key))[:4]
    keyindex = encode(i, 256, 4)
    I = hmac.new(chaincode, privkey_to_pubkey(key)+ encode(i, 256, 4), hashlib.sha512).digest()
    chaincode = encode(decode(I[32:], 256), 256, 32)
    newkey = encode((decode((I[:32]+B'\x01')[:32], 256) + decode(key[:32], 256)) % N, 256, 32)+b'\x01'
    newkey = b'\x00'+newkey[:-1]
    
    bindata = vbytes + bytes([depth % 256]) + fingerprint + keyindex + chaincode + newkey
    return encode(decode(bindata+ hashlib.sha256(hashlib.sha256(bindata).digest()).digest()[:4], 256), 58, 0)

print(bip32_ckd_prv(bip32_masterprivatekey, 1))


#Generate ckd publickey
def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    digest = hashlib.new('ripemd160', intermed).digest()
    return digest

def privkey_to_pubkey(privkey):
    privkey = decode(privkey, 256)
    return bytes([2+((fast_multiply(G, privkey)) [1] % 2)]) + encode((fast_multiply(G, privkey)) [0], 256, 32)


PRIVATE = [b'\x04\x88\xAD\xE4']
PUBLIC = [b'\x04\x88\xB2\x1E']
#----------------------------------------------------------------------------------------------------------    

def add_pubkeys(p1, p2):
    a = from_jacobian(jacobian_add(to_jacobian(decode_pubkey(p1)), to_jacobian(decode_pubkey(p2))))
    return bytes([2+((a)[1] % 2)])+ encode((a)[0], 256, 32)

def decode_pubkey(pub):
    x = decode(pub[1:33], 256)
    beta = pow(int(x*x*x+A*x+B), int((P+1)//4), int(P))#Tonelli–Shanks algorithm
    y = (P-beta) if ((beta + pub[0]) % 2) else beta#return(P-beta)when 1(pub is odd), return beta when 0 
    return (x, y)

def bip32_ckd_pub(data, i = int(i)):
    dbin = encode(decode(data, 58), 256, 0)
    vbytes = dbin[0:4]
    depth = dbin[4] + 1
    key = dbin[45:78]
    fingerprint = bin_hash160(key)[:4]
    i = encode(i, 256, 4)
    chaincode = dbin[13:45]
    I = hmac.new(chaincode, key + i, hashlib.sha512).digest()
    chaincode = encode(decode(I[32:], 256), 256, 32)
    pub = decode_pubkey(privkey_to_pubkey(I[:32]))
    keydata = add_pubkeys(bytes([2+((pub)[1] % 2)]) + encode((pub)[0], 256, 32), key)
    
    bindata = vbytes + bytes([depth % 256]) + fingerprint + i + chaincode + keydata
    string = bindata+hashlib.sha256(hashlib.sha256(bindata).digest()).digest()[:4]
    return encode(decode(string, 256), 58, 0)        

ckd_publickey  = bip32_ckd_pub(bip32_masterpublickey, 1)

print(ckd_publickey)