try:
    from Crypto.Hash import MD5
    from Crypto.Hash import SHA as SHA1
    from Crypto.Hash import SHA256
    from Crypto.Hash import SHA512
except ImportError:
    import hashlib
    MD5 = hashlib.md5
    SHA256 = hashlib.sha256
    SHA512 = hashlib.sha512
