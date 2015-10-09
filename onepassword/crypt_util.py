from __future__ import print_function

import base64
import binascii
import math
import struct

from . import padding
from . import pbkdf1
from . import pbkdf2
from .util import make_utf8

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import MD5, SHA256, SHA512, Hash
from cryptography.hazmat.primitives.hmac import HMAC

_backend = default_backend()


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
SALT_MARKER = b'Salted__'


class BadKeyError(Exception):
    pass


def a_decrypt_key(key_obj, password, aes_size=A_AES_SIZE):
    if not isinstance(password, bytes):
        password = password.encode('utf-8')
    key_size = KEY_SIZE[aes_size]
    data = base64.b64decode(key_obj['data'])
    salt = b'\x00'*SALT_SIZE
    if data[:len(SALT_MARKER)] == SALT_MARKER:
        salt = data[len(SALT_MARKER):len(SALT_MARKER) + SALT_SIZE]
        data = data[len(SALT_MARKER) + SALT_SIZE:]
    iterations = max(int(key_obj.get('iterations', DEFAULT_PBKDF_ITERATIONS)), MINIMUM_PBKDF_ITERATIONS)
    keys = pbkdf2.pbkdf2_sha1(password=password, salt=salt, length=2*key_size, iterations=iterations)
    key = keys[:key_size]
    iv = keys[key_size:]

    aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    decryptor = aes.decryptor()
    potential_key = padding.pkcs5_unpad(decryptor.update(data) + decryptor.finalize())

    validation = base64.b64decode(key_obj['validation'])
    decrypted_validation = a_decrypt_item(validation, potential_key)
    if decrypted_validation != potential_key:
        raise BadKeyError("Validation did not match")
    return potential_key


def hexize(byte_string):
    return binascii.hexlify(byte_string).upper()


def unhexize(hex_string):
    return binascii.unhexlify(hex_string)
    res = []
    if isinstance(hex_string, bytes):
        hex_string = hex_string.decode('ascii')
    for i in range(int(math.ceil(len(hex_string)/2.0))):
        conv = hex_string[2*i] + hex_string[2*i+1]
        res.append(int(conv, 16))
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
        digest = Hash(MD5(), backend=_backend)
        digest.update(key)
        nkey = digest.finalize()
        iv = '\x00'*key_size

    aes = Cipher(algorithms.AES(nkey), modes.CBC(iv), backend=_backend)
    decryptor = aes.decryptor()
    return padding.pkcs5_unpad(decryptor.update(data) + decryptor.finalize())


def opdata1_unpack(data):
    HEADER_LENGTH = 8
    TOTAL_HEADER_LENGTH = 32
    HMAC_LENGTH = 32
    if data[:HEADER_LENGTH] != b"opdata01":
        try:
            data = base64.b64decode(data)
        except binascii.Error:
            raise TypeError("expected opdata1 format message")
    if data[:HEADER_LENGTH] != b"opdata01":
        raise TypeError("expected opdata1 format message")
    plaintext_length, iv = struct.unpack("<Q16s", data[HEADER_LENGTH:TOTAL_HEADER_LENGTH])
    cryptext = data[TOTAL_HEADER_LENGTH:-HMAC_LENGTH]
    expected_hmac = data[-HMAC_LENGTH:]
    hmac_d_data = data[:-HMAC_LENGTH]
    return plaintext_length, iv, cryptext, expected_hmac, hmac_d_data


def opdata1_decrypt_key(data, key, hmac_key, aes_size=C_AES_SIZE, ignore_hmac=False):
    """Decrypt encrypted item keys"""
    hmac_key = make_utf8(hmac_key)
    key_size = KEY_SIZE[aes_size]
    iv, cryptext, expected_hmac = struct.unpack("=16s64s32s", data)
    if not ignore_hmac:
        verifier = HMAC(hmac_key, SHA256(), backend=_backend)
        verifier.update(iv + cryptext)
        try:
            verifier.verify(expected_hmac)
        except InvalidSignature:
            raise ValueError("HMAC did not match for opdata1 key")
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    decryptor = aes.decryptor()
    decrypted = decryptor.update(cryptext) + decryptor.finalize()
    crypto_key, mac_key = decrypted[:key_size], decrypted[key_size:]
    return crypto_key, mac_key


def opdata1_decrypt_master_key(data, key, hmac_key, aes_size=C_AES_SIZE, ignore_hmac=False):
    key_size = KEY_SIZE[aes_size]
    bare_key = opdata1_decrypt_item(data, key, hmac_key, aes_size=aes_size, ignore_hmac=ignore_hmac)
    # XXX: got the following step from jeff@agilebits (as opposed to the
    # docs anywhere)
    digest = Hash(SHA512(), backend=_backend)
    digest.update(bare_key)
    hashed_key = digest.finalize()
    return hashed_key[:key_size], hashed_key[key_size:]


def opdata1_decrypt_item(data, key, hmac_key, aes_size=C_AES_SIZE, ignore_hmac=False):
    key_size = KEY_SIZE[aes_size]
    assert len(key) == key_size
    assert len(data) >= OPDATA1_MINIMUM_SIZE
    plaintext_length, iv, cryptext, expected_hmac, hmac_d_data = opdata1_unpack(data)
    if not ignore_hmac:
        verifier = HMAC(hmac_key, SHA256(), backend=_backend)
        verifier.update(hmac_d_data)
        if len(verifier.copy().finalize()) != len(expected_hmac):
            raise ValueError("Got unexpected HMAC length (expected %d bytes, got %d bytes)" % (
                len(expected_hmac),
                len(got_hmac)
            ))
        try:
            verifier.verify(expected_hmac)
        except InvalidSignature:
            raise ValueError("HMAC did not match for opdata1 record")
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_backend)
    decryptor = aes.decryptor()
    decrypted = decryptor.update(cryptext) + decryptor.finalize()
    unpadded = padding.ab_unpad(decrypted, plaintext_length)
    return unpadded


def opdata1_derive_keys(password, salt, iterations=1000, aes_size=C_AES_SIZE):
    """Key derivation function for .cloudkeychain files"""
    key_size = KEY_SIZE[aes_size]
    password = password.encode('utf-8')
    # TODO: is this necessary? does the hmac on ios actually include the
    # trailing nul byte?
    password += b'\x00'
    keys = pbkdf2.pbkdf2_sha512(password=password, salt=salt, length=2*key_size, iterations=iterations)
    key1 = keys[:key_size]
    key2 = keys[key_size:]
    return key1, key2


def opdata1_verify_overall_hmac(hmac_key, item):
    verifier = HMAC(hmac_key, SHA256(), backend=_backend)
    for key, value in sorted(item.items()):
        if key == 'hmac':
            continue
        if isinstance(value, bool):
            value = str(int(value)).encode('utf-8')
        else:
            value = str(value).encode('utf-8')
        verifier.update(key.encode('utf-8'))
        verifier.update(value)
    expected = base64.b64decode(item['hmac'])
    try:
        verifier.verify(expected)
    except InvalidSignature:
        raise ValueError("HMAC did not match for data dictionary")
