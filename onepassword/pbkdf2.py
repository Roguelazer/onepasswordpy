from __future__ import absolute_import

try:
    from ._pbkdf2_nettle import pbkdf2_sha1, pbkdf2_sha512
    # make pyflakes happy
    pbkdf2_sha1 = pbkdf2_sha1
    pbkdf2_sha512 = pbkdf2_sha512
except ImportError:
    from ._pbkdf2_cryptography import pbkdf2_sha1, pbkdf2_sha512
    # make pyflakes happy
    pbkdf2_sha1 = pbkdf2_sha1
    pbkdf2_sha512 = pbkdf2_sha512
