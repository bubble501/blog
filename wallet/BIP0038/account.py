from binascii import hexlify, unhexlify
import ecdsa
import hashlib
import sys
import string
import logging
log = logging.getLogger(__name__)


""" This class and the methods require python3 """
assert sys.version_info[0] == 3, "graphenelib requires python3"

""" Default Prefix """
PREFIX = "GPH"

known_prefixes = [
    PREFIX,
    "BTS",
    "MUSE",
    "TEST",
    "STM",
    "GLX",
    "GLS",
]


class Base58(object):
    """Base58 base class
    This class serves as an abstraction layer to deal with base58 encoded
    strings and their corresponding hex and binary representation throughout the
    library.
    :param data: Data to initialize object, e.g. pubkey data, address data, ...
    :type data: hex, wif, bip38 encrypted wif, base58 string
    :param str prefix: Prefix to use for Address/PubKey strings (defaults to ``GPH``)
    :return: Base58 object initialized with ``data``
    :rtype: Base58
    :raises ValueError: if data cannot be decoded
    * ``bytes(Base58)``: Returns the raw data
    * ``str(Base58)``:   Returns the readable ``Base58CheckEncoded`` data.
    * ``repr(Base58)``:  Gives the hex representation of the data.
    *  ``format(Base58,_format)`` Formats the instance according to ``_format``:
        * ``"btc"``: prefixed with ``0x80``. Yields a valid btc address
        * ``"wif"``: prefixed with ``0x00``. Yields a valid wif key
        * ``"bts"``: prefixed with ``BTS``
        * etc.
    """
    def __init__(self, data, prefix=PREFIX):
        self._prefix = prefix
        if all(c in string.hexdigits for c in data):
            self._hex = data
        elif data[0] == "5" or data[0] == "6":
            self._hex = base58CheckDecode(data)
        elif data[0] == "K" or data[0] == "L":
            self._hex = base58CheckDecode(data)[:-2]
        elif data[:len(self._prefix)] == self._prefix:
            self._hex = gphBase58CheckDecode(data[len(self._prefix):])
        else:
            raise ValueError("Error loading Base58 object")

    def __format__(self, _format):
        """ Format output according to argument _format (wif,btc,...)
            :param str _format: Format to use
            :return: formatted data according to _format
            :rtype: str
        """
        if _format.upper() == "WIF":
            return base58CheckEncode(0x80, self._hex)
        elif _format.upper() == "ENCWIF":
            return base58encode(self._hex)
        elif _format.upper() == "BTC":
            return base58CheckEncode(0x00, self._hex)
        elif _format.upper() in known_prefixes:
            return _format.upper() + str(self)
        else:
            log.warn("Format %s unkown. You've been warned!\n" % _format)
            return _format.upper() + str(self)

    def __repr__(self):
        """ Returns hex value of object
            :return: Hex string of instance's data
            :rtype: hex string
        """
        return self._hex

    def __str__(self):
        """ Return graphene-base58CheckEncoded string of data
            :return: Base58 encoded data
            :rtype: str
        """
        return gphBase58CheckEncode(self._hex)

    def __bytes__(self):
        """ Return raw bytes
            :return: Raw bytes of instance
            :rtype: bytes
        """
        return unhexlify(self._hex)


# https://github.com/tochev/python3-cryptocoins/raw/master/cryptocoins/base58.py
BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58decode(base58_str):
    base58_text = bytes(base58_str, "ascii")
    n = 0
    leading_zeroes_count = 0
    for b in base58_text:
        n = n * 58 + BASE58_ALPHABET.find(b)
        if n == 0:
            leading_zeroes_count += 1
    res = bytearray()
    while n >= 256:
        div, mod = divmod(n, 256)
        res.insert(0, mod)
        n = div
    else:
        res.insert(0, n)
    return hexlify(bytearray(1) * leading_zeroes_count + res).decode('ascii')


def base58encode(hexstring):
    byteseq = bytes(unhexlify(bytes(hexstring, 'ascii')))
    n = 0
    leading_zeroes_count = 0
    for c in byteseq:
        n = n * 256 + c
        if n == 0:
            leading_zeroes_count += 1
    res = bytearray()
    while n >= 58:
        div, mod = divmod(n, 58)
        res.insert(0, BASE58_ALPHABET[mod])
        n = div
    else:
        res.insert(0, BASE58_ALPHABET[n])
    return (BASE58_ALPHABET[0:1] * leading_zeroes_count + res).decode('ascii')


def ripemd160(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(unhexlify(s))
    return ripemd160.digest()


def doublesha256(s):
    return hashlib.sha256(hashlib.sha256(unhexlify(s)).digest()).digest()


def b58encode(v):
    return base58encode(v)


def b58decode(v):
    return base58decode(v)


def base58CheckEncode(version, payload):
    s = ('%.2x' % version) + payload
    checksum = doublesha256(s)[:4]
    result = s + hexlify(checksum).decode('ascii')
    return base58encode(result)


def base58CheckDecode(s):
    s = unhexlify(base58decode(s))
    dec = hexlify(s[:-4]).decode('ascii')
    checksum = doublesha256(dec)[:4]
    assert(s[-4:] == checksum)
    return dec[2:]


def gphBase58CheckEncode(s):
    checksum = ripemd160(s)[:4]
    result = s + hexlify(checksum).decode('ascii')
    return base58encode(result)


def gphBase58CheckDecode(s):
    s = unhexlify(base58decode(s))
    dec = hexlify(s[:-4]).decode('ascii')
    checksum = ripemd160(dec)[:4]
    assert(s[-4:] == checksum)
    return dec




class Address(object):
    """ Address class
        This class serves as an address representation for Public Keys.
        :param str address: Base58 encoded address (defaults to ``None``)
        :param str pubkey: Base58 encoded pubkey (defaults to ``None``)
        :param str prefix: Network prefix (defaults to ``GPH``)
        Example::
           Address("GPHFN9r6VYzBK8EKtMewfNbfiGCr56pHDBFi")
    """
    def __init__(self, address=None, pubkey=None, prefix="GPH"):
        self.prefix = prefix
        if pubkey is not None:
            self._pubkey = Base58(pubkey, prefix=prefix)
            self._address = None
        elif address is not None:
            self._pubkey = None
            self._address = Base58(address, prefix=prefix)
        else:
            raise Exception("Address has to be initialized by either the " +
                            "pubkey or the address.")

    def derivesha256address(self):
        """ Derive address using ``RIPEMD160(SHA256(x))`` """
        pkbin = unhexlify(repr(self._pubkey))
        addressbin = ripemd160(hexlify(hashlib.sha256(pkbin).digest()))
        return Base58(hexlify(addressbin).decode('ascii'))

    def derivesha512address(self):
        """ Derive address using ``RIPEMD160(SHA512(x))`` """
        pkbin = unhexlify(repr(self._pubkey))
        addressbin = ripemd160(hexlify(hashlib.sha512(pkbin).digest()))
        return Base58(hexlify(addressbin).decode('ascii'))

    def __repr__(self):
        """ Gives the hex representation of the ``GrapheneBase58CheckEncoded``
            Graphene address.
        """
        return repr(self.derivesha512address())

    def __str__(self):
        """ Returns the readable Graphene address. This call is equivalent to
            ``format(Address, "GPH")``
        """
        return format(self, self.prefix)

    def __format__(self, _format):
        """  May be issued to get valid "MUSE", "PLAY" or any other Graphene compatible
            address with corresponding prefix.
        """
        if self._address is None:
            if _format.lower() == "btc":
                return format(self.derivesha256address(), _format)
            else:
                return format(self.derivesha512address(), _format)
        else:
            return format(self._address, _format)

    def __bytes__(self):
        """ Returns the raw content of the ``Base58CheckEncoded`` address """
        if self._address is None:
            return bytes(self.derivesha512address())
        else:
            return bytes(self._address)



class PublicKey(Address):
    """ This class deals with Public Keys and inherits ``Address``.
        :param str pk: Base58 encoded public key
        :param str prefix: Network prefix (defaults to ``GPH``)
        Example:::
           PublicKey("GPH6UtYWWs3rkZGV8JA86qrgkG6tyFksgECefKE1MiH4HkLD8PFGL")
        .. note:: By default, graphene-based networks deal with **compressed**
                  public keys. If an **uncompressed** key is required, the
                  method ``unCompressed`` can be used::
                      PublicKey("xxxxx").unCompressed()
    """
    def __init__(self, pk, prefix="GPH"):
        self.prefix = prefix
        self._pk = Base58(pk, prefix=prefix)
        self.address = Address(pubkey=pk, prefix=prefix)
        self.pubkey = self._pk

    def _derive_y_from_x(self, x, is_even):
        """ Derive y point from x point """
        curve = ecdsa.SECP256k1.curve
        # The curve equation over F_p is:
        #   y^2 = x^3 + ax + b
        a, b, p = curve.a(), curve.b(), curve.p()
        alpha = (pow(x, 3, p) + a * x + b) % p
        beta = ecdsa.numbertheory.square_root_mod_prime(alpha, p)
        if (beta % 2) == is_even:
            beta = p - beta
        return beta

    def compressed(self):
        """ Derive compressed public key """
        order = ecdsa.SECP256k1.generator.order()
        p = ecdsa.VerifyingKey.from_string(bytes(self), curve=ecdsa.SECP256k1).pubkey.point
        x_str = ecdsa.util.number_to_string(p.x(), order)
        # y_str = ecdsa.util.number_to_string(p.y(), order)
        compressed = hexlify(bytes(chr(2 + (p.y() & 1)), 'ascii') + x_str).decode('ascii')
        return(compressed)

    def unCompressed(self):
        """ Derive uncompressed key """
        public_key = repr(self._pk)
        prefix = public_key[0:2]
        if prefix == "04":
            return public_key
        assert prefix == "02" or prefix == "03"
        x = int(public_key[2:], 16)
        y = self._derive_y_from_x(x, (prefix == "02"))
        key = '04' + '%064x' % x + '%064x' % y
        return key

    def point(self):
        """ Return the point for the public key """
        string = unhexlify(self.unCompressed())
        return ecdsa.VerifyingKey.from_string(string[1:], curve=ecdsa.SECP256k1).pubkey.point

    def __repr__(self):
        """ Gives the hex representation of the Graphene public key. """
        return repr(self._pk)

    def __str__(self):
        """ Returns the readable Graphene public key. This call is equivalent to
            ``format(PublicKey, "GPH")``
        """
        return format(self._pk, self.prefix)

    def __format__(self, _format):
        """ Formats the instance of:doc:`Base58 <base58>` according to ``_format`` """
        return format(self._pk, _format)

    def __bytes__(self):
        """ Returns the raw public key (has length 33)"""
        return bytes(self._pk)








class PrivateKey(PublicKey):
    """ Derives the compressed and uncompressed public keys and
        constructs two instances of ``PublicKey``:
        :param str wif: Base58check-encoded wif key
        :param str prefix: Network prefix (defaults to ``GPH``)
        Example:::
            PrivateKey("5HqUkGuo62BfcJU5vNhTXKJRXuUi9QSE6jp8C3uBJ2BVHtB8WSd")
        Compressed vs. Uncompressed:
        * ``PrivateKey("w-i-f").pubkey``:
            Instance of ``PublicKey`` using compressed key.
        * ``PrivateKey("w-i-f").pubkey.address``:
            Instance of ``Address`` using compressed key.
        * ``PrivateKey("w-i-f").uncompressed``:
            Instance of ``PublicKey`` using uncompressed key.
        * ``PrivateKey("w-i-f").uncompressed.address``:
            Instance of ``Address`` using uncompressed key.
    """
    def __init__(self, wif=None, prefix="GPH"):
        if wif is None:
            import os
            self._wif = Base58(hexlify(os.urandom(32)).decode('ascii'))
        elif isinstance(wif, Base58):
            self._wif = wif
        else:
            self._wif = Base58(wif)
        # compress pubkeys only
        self._pubkeyhex, self._pubkeyuncompressedhex = self.compressedpubkey()
        self.pubkey = PublicKey(self._pubkeyhex, prefix=prefix)
        self.uncompressed = PublicKey(self._pubkeyuncompressedhex, prefix=prefix)
        self.uncompressed.address = Address(pubkey=self._pubkeyuncompressedhex, prefix=prefix)
        self.address = Address(pubkey=self._pubkeyhex, prefix=prefix)

    def compressedpubkey(self):
        """ Derive uncompressed public key """
        secret = unhexlify(repr(self._wif))
        order = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1).curve.generator.order()
        p = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1).verifying_key.pubkey.point
        x_str = ecdsa.util.number_to_string(p.x(), order)
        y_str = ecdsa.util.number_to_string(p.y(), order)
        compressed = hexlify(bytes(chr(2 + (p.y() & 1)), 'ascii') + x_str).decode('ascii')
        uncompressed = hexlify(bytes(chr(4), 'ascii') + x_str + y_str).decode('ascii')
        return([compressed, uncompressed])

    def __format__(self, _format):
        """ Formats the instance of:doc:`Base58 <base58>` according to
            ``_format``
        """
        return format(self._wif, _format)

    def __repr__(self):
        """ Gives the hex representation of the Graphene private key."""
        return repr(self._wif)

    def __str__(self):
        """ Returns the readable (uncompressed wif format) Graphene private key. This
            call is equivalent to ``format(PrivateKey, "WIF")``
        """
        return format(self._wif, "WIF")

    def __bytes__(self):
        """ Returns the raw private key """
        return bytes(self._wif)