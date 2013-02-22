import base64
import struct

import Crypto.Cipher.AES
import Crypto.Hash.HMAC
import Crypto.Hash.MD5
import Crypto.Hash.SHA
import Crypto.Hash.SHA256
import Crypto.Hash.SHA512
import Crypto.Protocol.KDF

from . import padding
from . import pbkdf1


# 8 bytes for "opdata1"
# 8 bytes for plaintext length
# 16 bytes for IV
# 16 bytes for mimum cryptext size
# 32 bytes for HMAC-SHA256
OPDATA1_MINIMUM_SIZE = 80


DEFAULT_PBKDF_ITERATIONS = 1000
MINIMUM_PBKDF_ITERATIONS = 1000

A_AES_SIZE = 128
C_AES_SIZE = 256
KEY_SIZE = {
    128: 16,
    192: 24,
    256: 32,
}

SALT_SIZE = 8
SALT_MARKER = 'Salted__'


class BadKeyError(Exception):
    pass


def a_decrypt_key(key_obj, password, aes_size=A_AES_SIZE):
    key_size = KEY_SIZE[aes_size]
    data = base64.b64decode(key_obj['data'])
    salt = '\x00'*SALT_SIZE
    if data[:len(SALT_MARKER)] == SALT_MARKER:
        salt = data[len(SALT_MARKER):len(SALT_MARKER) + SALT_SIZE]
        data = data[len(SALT_MARKER) + SALT_SIZE:]
    iterations = max(int(key_obj.get('iterations', DEFAULT_PBKDF_ITERATIONS)), MINIMUM_PBKDF_ITERATIONS)
    prf = lambda p,s: Crypto.Hash.HMAC.new(p, s, digestmod=Crypto.Hash.SHA).digest()
    keys = Crypto.Protocol.KDF.PBKDF2(password=password, salt=salt, dkLen=2*key_size, count=iterations, prf=prf)
    key = keys[:key_size]
    iv = keys[key_size:]
    aes_er = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    potential_key = padding.pkcs5_unpad(aes_er.decrypt(data))
    validation = base64.b64decode(key_obj['validation'])
    decrypted_validation = a_decrypt_item(validation, potential_key)
    if decrypted_validation != potential_key:
        raise BadKeyError("Validation did not match")
    return potential_key


def hexize(byte_string):
    res = []
    for c in byte_string:
        res.append('%02x' % ord(c))
    return ''.join(res).upper()

def unhexize(hex_string):
    res = []
    for i in range(len(hex_string)/2):
        res.append(int((hex_string[2*i] + hex_string[2*i+1]), 16))
    return ''.join(chr(i) for i in res)


def a_decrypt_item(data, key, aes_size=A_AES_SIZE):
    key_size = KEY_SIZE[aes_size]
    if data[:len(SALT_MARKER)] == SALT_MARKER:
        salt = data[len(SALT_MARKER):len(SALT_MARKER) + SALT_SIZE]
        data = data[len(SALT_MARKER) + SALT_SIZE:]
        pb_gen = pbkdf1.PBKDF1(key, salt)
        nkey = pb_gen.read(key_size)
        iv = pb_gen.read(key_size)
    else:
        nkey = Crypto.Hash.MD5.new(key).digest()
        iv = '\x00'*key_size
    aes_er = Crypto.Cipher.AES.new(nkey, Crypto.Cipher.AES.MODE_CBC, iv)
    return padding.pkcs5_unpad(aes_er.decrypt(data))


def opdata1_unpack(data):
    HEADER_LENGTH = 8
    TOTAL_HEADER_LENGTH = 32
    HMAC_LENGTH = 32
    if data[:HEADER_LENGTH] != "opdata01":
        data = base64.b64decode(data)
    if data[:HEADER_LENGTH] != "opdata01":
        raise TypeError("expected opdata1 format message")
    plaintext_length, iv = struct.unpack("<Q16s", data[HEADER_LENGTH:TOTAL_HEADER_LENGTH])
    cryptext = data[TOTAL_HEADER_LENGTH:-HMAC_LENGTH]
    expected_hmac = data[-HMAC_LENGTH:]
    hmac_d_data = data[:-HMAC_LENGTH]
    return plaintext_length, iv, cryptext, expected_hmac, hmac_d_data


def opdata1_decrypt_key(data, key, hmac_key, aes_size=C_AES_SIZE, ignore_hmac=False):
    """Decrypt encrypted item keys"""
    key_size = KEY_SIZE[aes_size]
    iv, cryptext, expected_hmac = struct.unpack("=16s64s32s", data)
    if not ignore_hmac:
        verifier = Crypto.Hash.HMAC.new(key=hmac_key, msg=(iv + cryptext), digestmod=Crypto.Hash.SHA256)
        if verifier.digest() != expected_hmac:
            raise ValueError("HMAC did not match for opdata1 key")
    decryptor = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    decrypted = decryptor.decrypt(cryptext)
    crypto_key, mac_key = decrypted[:key_size], decrypted[key_size:]
    return crypto_key, mac_key


def opdata1_decrypt_master_key(data, key, hmac_key, aes_size=C_AES_SIZE, ignore_hmac=False):
    key_size = KEY_SIZE[aes_size]
    bare_key = opdata1_decrypt_item(data, key, hmac_key, aes_size=aes_size, ignore_hmac=ignore_hmac)
    # XXX: got the following step from jeff@agilebits (as opposed to the
    # docs anywhere)
    hashed_key = Crypto.Hash.SHA512.new(bare_key).digest()
    return hashed_key[:key_size], hashed_key[key_size:]


def opdata1_decrypt_item(data, key, hmac_key, aes_size=C_AES_SIZE, ignore_hmac=False):
    key_size = KEY_SIZE[aes_size]
    assert len(key) == key_size
    assert len(data) >= OPDATA1_MINIMUM_SIZE
    plaintext_length, iv, cryptext, expected_hmac, hmac_d_data = opdata1_unpack(data)
    if not ignore_hmac:
        verifier = Crypto.Hash.HMAC.new(key=hmac_key, msg=hmac_d_data, digestmod=Crypto.Hash.SHA256)
        got_hmac = verifier.digest()
        if len(got_hmac) != len(expected_hmac):
            raise ValueError("Got unexpected HMAC length (expected %d bytes, got %d bytes)" % (len(expected_hmac), len(got_hmac)))
        if got_hmac != expected_hmac:
            raise ValueError("HMAC did not match for opdata1 record")
    decryptor = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    decrypted = decryptor.decrypt(cryptext)
    unpadded = padding.ab_unpad(decrypted, plaintext_length)
    return unpadded


def opdata1_derive_keys(password, salt, iterations=1000, aes_size=C_AES_SIZE):
    """Key derivation function for .cloudkeychain files"""
    key_size = KEY_SIZE[aes_size]
    password = password.encode('utf-8')
    # TODO: is this necessary? does the hmac on ios actually include the
    # trailing nul byte?
    password += "\x00"
    prf = lambda p,s: Crypto.Hash.HMAC.new(p, s, digestmod=Crypto.Hash.SHA512).digest()
    keys = Crypto.Protocol.KDF.PBKDF2(password=password, salt=salt, dkLen=2*key_size, count=iterations, prf=prf)
    key1 = keys[:key_size]
    key2 = keys[key_size:]
    return key1, key2
