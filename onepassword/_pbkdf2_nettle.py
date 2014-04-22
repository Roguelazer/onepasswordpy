import ctypes
import ctypes.util

"""Simple ctypes wrapper around nettle. Idea came from https://github.com/fredrikt/python-ndnkdf"""


_nettle = ctypes.cdll.LoadLibrary(ctypes.util.find_library('nettle'))
for function in ('nettle_hmac_sha1_update', 'nettle_hmac_sha512_update', 'nettle_hmac_sha1_digest', 'nettle_hmac_sha512_digest', 'nettle_pbkdf2'):
    if not hasattr(_nettle, function):
        raise ImportError(function)


def _pbkdf2(password, salt, length, iterations, hash_size, set_fn, update_fn, digest_fn):
    buf = ctypes.create_string_buffer(b'', size=max(length, hash_size))
    # TODO: 1024 bytes is almost definitely not the size of this structure
    shactx = ctypes.create_string_buffer(b'', size=1024)
    set_fn(ctypes.byref(shactx), len(password), password)
    _nettle.nettle_pbkdf2(
        ctypes.byref(shactx),
        update_fn,
        digest_fn,
        hash_size, int(iterations),
        len(salt), salt,
        max(length, hash_size), ctypes.byref(buf))
    return buf.raw[:length]


def pbkdf2_sha1(password, salt, length, iterations):
    return _pbkdf2(password, salt, length, iterations, 20, _nettle.nettle_hmac_sha1_set_key, _nettle.nettle_hmac_sha1_update, _nettle.nettle_hmac_sha1_digest)


def pbkdf2_sha512(password, salt, length, iterations):
    return _pbkdf2(password, salt, length, iterations, 64, _nettle.nettle_hmac_sha512_set_key, _nettle.nettle_hmac_sha512_update, _nettle.nettle_hmac_sha512_digest)
