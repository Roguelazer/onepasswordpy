import base64
import hashlib

import Crypto.Cipher.AES
import pbkdf2


DEFAULT_PBKDF_ITERATIONS = 1000
MINIMUM_PBKDF_ITERATIONS = 1000

AES_SIZE = 128
KEY_SIZE = (AES_SIZE) / 8
KDF_ROUNDS_BY_SIZE = {
    128: 2,
    192: 2,
    256: 3,
}

SALT_SIZE = 8
SALT_MARKER = 'Salted__'


class BadKeyError(Exception):
    pass


# largely inspired from 
# http://stackoverflow.com/questions/12562021/aes-decryption-padding-with-pkcs5-python
def pad(string, block_size=16):
    """PKCS#5 pad the given string to the given block size
    
    Aguments:
        string - the string to pad. should be bytes()
        block_size - the amount to pad to in bytes
    """
    if block_size <= 0:
        raise ValueError("block_size must be a positive integer")
    return string + (block_size - len(string) % block_size) * chr(block_size - len(string) % block_size)


def unpad(string):
    """PKCS#5 unpad the given string"""
    amount_of_padding = ord(string[-1])
    return string[:-amount_of_padding]


def decrypt_key(key_obj, password):
    data = base64.b64decode(key_obj['data'])
    salt = '\x00'*SALT_SIZE
    if data[:len(SALT_MARKER)] == SALT_MARKER:
        salt = data[len(SALT_MARKER):len(SALT_MARKER) + SALT_SIZE]
        data = data[len(SALT_MARKER) + SALT_SIZE:]
    iterations = max(int(key_obj.get('iterations', DEFAULT_PBKDF_ITERATIONS)), MINIMUM_PBKDF_ITERATIONS)
    pb_gen = pbkdf2.PBKDF2(password, salt, iterations)
    key = pb_gen.read(KEY_SIZE)
    iv = pb_gen.read(KEY_SIZE)
    aes_er = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    potential_key = unpad(aes_er.decrypt(data))
    validation = base64.b64decode(key_obj['validation'])
    decrypted_validation = decrypt_item(validation, potential_key)
    if decrypted_validation != potential_key:
        raise BadKeyError("Validation did not match")
    return potential_key


def _openssl_kdf(key, salt=('\x00'*KEY_SIZE)):
    # TODO: Call m2crypto's EVP_BytesToKey instead
    rounds = KDF_ROUNDS_BY_SIZE[AES_SIZE]
    hashes = []
    ks = key + salt
    result = bytes()
    hashes.append(hashlib.md5(ks).digest())
    for i in range(rounds):
        tohash = ks if i == 0 else (hashes[i-1] + ks)
        this_hash = hashlib.md5(tohash).digest()
        hashes.append(this_hash)
        result += this_hash
    return result[:-KEY_SIZE], result[-KEY_SIZE:]


def decrypt_item(data, key):
    if data[:len(SALT_MARKER)] == SALT_MARKER:
        salt = data[len(SALT_MARKER):len(SALT_MARKER) + SALT_SIZE]
        data = data[len(SALT_MARKER) + SALT_SIZE:]
        nkey, iv = _openssl_kdf(key, salt)
    else:
        nkey = hashlib.md5(key).digest()
        iv = '\x00'*KEY_SIZE
    aes_er = Crypto.Cipher.AES.new(nkey, Crypto.Cipher.AES.MODE_CBC, iv)
    return unpad(aes_er.decrypt(data))
