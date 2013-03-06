try:
    from _pbkdf2_m2crypto import *
except ImportError:
    from _pbkdf2_pycrypto import *
