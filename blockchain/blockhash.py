import hashlib
import binascii
import re

#little edian function
def endian(src):
    scr = ''.join(re.split('(..)',src)[1::2][::-1])
    return scr

#block data(from blockchain info)
block_version = "00000004"
previous_block_hash = "0000000000000000005629ef6b683f8f6301c7e6f8e796e7c58702a079db14e8"
block_merkle_root = "efb8011cb97b5f1599b2e18f200188f1b8207da2884392672f92ac7985534eeb"
block_time = "2016-01-30 13:23:09"
block_bits = "403253488"
block_nonce = "1448681410"

#convert little endian
block_version       = endian(block_version)
previous_block_hash = endian(previous_block_hash)
block_merkle_root   = endian(block_merkle_root)

#convert GMT to unix
from datetime import datetime
block_time = int((datetime.strptime(block_time, "%Y-%m-%d %H:%M:%S")-datetime(1970,1,1)).total_seconds())
block_time = endian(format(block_time,"x"))

#convert decimal to hexadecimal
block_bits = endian('%x' % int(block_bits))
block_nonce = endian('%x' % int(block_nonce))

#block header
block_data = block_version + previous_block_hash + block_merkle_root + block_time + block_bits + block_nonce
#calcurate 
hash = hashlib.sha256(hashlib.sha256(binascii.a2b_hex(block_data)).digest()).digest()
hash = endian(binascii.b2a_hex(hash).decode('utf-8'))
hash 