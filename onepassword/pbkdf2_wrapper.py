"""Glue module to support the many different vendor implementations of PBKDF2"""


sources = ['onepassword.%s' % s for s in ('_pbkdf2_nettle', '_pbkdf2_m2crypyo', '_pbkdf2_pycrypto', '_pbkdf2_pbkdf2')]
functions = ('pbkdf2_sha1', 'pbkdf2_sha512')

for source in sources:
    try:
        _temp = __import__(source, functions, globals(), locals(), level=-1)
        for function in functions:
            locals()[function] = getattr(_temp, function)
        break
    except ImportError:
        pass
else:
    raise ImportError

__all__ = functions
