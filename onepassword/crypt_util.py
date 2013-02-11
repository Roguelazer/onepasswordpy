import base64
import hashlib

import Crypto.Cipher.AES
import pbkdf2


DEFAULT_PBKDF_ITERATIONS = 1000
MINIMUM_PBKDF_ITERATIONS = 1000

AES_SIZE = 128
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
    # preserve empty strings
    if not string:
        return string
    amount_of_padding = ord(string[-1])
    return string[:-amount_of_padding]


def decrypt_key(key_obj, password, aes_size=AES_SIZE):
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
    potential_key = unpad(aes_er.decrypt(data))
    validation = base64.b64decode(key_obj['validation'])
    decrypted_validation = decrypt_item(validation, potential_key)
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


def decrypt_item(data, key, aes_size=AES_SIZE):
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
    return unpad(aes_er.decrypt(data))
