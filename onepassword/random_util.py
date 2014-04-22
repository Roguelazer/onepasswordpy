"""Random sources"""

import os
import random

import six


# If someone's truly paranoid and wants to contribute
# code that knows how to talk to an EGD for really really
# strong randomness, I would not say no to that. but it's
# almost always safer/smarter to just use /dev/random and
# trust that your sysadmin knows how to use the EGD


def really_random_bytes(l):
    """Return bytes that should be cryptographically strong (generally, a
    PRNG regularly seeded with real-world entropy"""
    with open("/dev/random", "rb") as f:
        return f.read(l)


def sort_of_random_bytes(l):
    """Return bytes that may be cryptographically strong or may be
    PRNG-based depending on the operating system status"""
    return os.urandom(l)


def barely_random_bytes(l):
    """Return bytes that appear random but are not cryptographically
    strong"""
    return b''.join(six.int2byte(random.randrange(0, 255)) for b in six.moves.range(l))


def not_random_bytes(l):
    """Return bytes that are not at all random, but suitable for use as
    testing filler"""
    return b''.join(six.int2byte(x % 255) for x in six.moves.range(l))
