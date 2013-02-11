import base64
import hashlib
import hmac
import struct

import Crypto.Cipher.AES
import pbkdf2

from . import padding


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
KDF_ROUNDS_BY_SIZE = {
    128: 2,
    192: 2,
    256: 3,
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
    pb_gen = pbkdf2.PBKDF2(password, salt, iterations)
    key = pb_gen.read(key_size)
    iv = pb_gen.read(key_size)
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


def pbkdf1(key, salt=None, key_size=16, rounds=2, hash_algo=hashlib.md5, count=1):
    """Reimplement the simple PKCS#5 v1.5 key derivation function from OpenSSL
    
    (as in `openssl enc`). Technically, this is only PBKDF1 if the key size is 
    20 bytes or less. But whatever.
    """
    # TODO: Call openssl's EVP_BytesToKey instead of reimplementing by hand
    # (through m2crypto?)
    if salt is None:
        salt = '\x00'*(key_size/2)
    ks = key + salt
    d = ['']
    result = bytes()
    i = 1
    while len(result) < 2*key_size:
        tohash = d[i-1] + ks
        # man page for BytesTo
        for hash_application in range(count):
            tohash = hash_algo(tohash).digest()
        d.append(tohash)
        result = ''.join(d)
        i += 1
    return result[:-key_size], result[-key_size:]


def a_decrypt_item(data, key, aes_size=A_AES_SIZE):
    key_size = KEY_SIZE[aes_size]
    if data[:len(SALT_MARKER)] == SALT_MARKER:
        salt = data[len(SALT_MARKER):len(SALT_MARKER) + SALT_SIZE]
        data = data[len(SALT_MARKER) + SALT_SIZE:]
        kdf_rounds = KDF_ROUNDS_BY_SIZE[aes_size]
        nkey, iv = pbkdf1(key, salt, key_size=key_size, rounds=kdf_rounds)
    else:
        nkey = hashlib.md5(key).digest()
        iv = '\x00'*key_size
    aes_er = Crypto.Cipher.AES.new(nkey, Crypto.Cipher.AES.MODE_CBC, iv)
    return padding.pkcs5_unpad(aes_er.decrypt(data))


def opdata1_decrypt_item(data, key, hmac_key, aes_size=C_AES_SIZE):
    key_size = KEY_SIZE[aes_size]
    assert len(key) == key_size
    assert len(data) >= OPDATA1_MINIMUM_SIZE
    assert data[:8] == "opdata1", "expected opdata1 format message"
    data = data[8:]
    plaintext_length = struct.unpack("<Q", data[:8])
    iv = data[8:24]
    cryptext = data[24:-32]
    expected_hmac = data[-32:]
    verifier = hmac.new(key=hmac_key, digestmod=hashlib.sha256)
    # TODO: put in "opdata1" and plantext_length or not?
    verifier.update(iv)
    verifier.update(cryptext)
    if verifier.digest() != expected_hmac:
        raise ValueError("HMAC did not match for opdata1 record")
    decryptor = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    return padding.ab_unpad(decryptor.decrypt(data), plaintext_length)
