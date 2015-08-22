import os

import six


def pkcs5_pad(string, block_size=16):
    """PKCS#5 pad the given string to the given block size

    Aguments:
        string - the string to pad. should be bytes()
        block_size - the amount to pad to in bytes
    """
    if block_size <= 0:
        raise ValueError("block_size must be a positive integer")
    return string + (block_size - len(string) % block_size) * six.int2byte(block_size - len(string) % block_size)


def pkcs5_unpad(string):
    """PKCS#5 unpad the given string"""
    # preserve empty strings
    if not string:
        return string
    amount_of_padding = six.indexbytes(string, -1)
    return string[:-amount_of_padding]


def ab_pad(string, block_size=16, random_generator=os.urandom):
    """AgileBits custom pad a string to the given block size

    Arguments:
        string - The string to pad
        block_size - Block size in bytes
        random_generator - A function that returns random bytes
    """
    bytes_to_pad = block_size - (len(string) % block_size)
    padding = random_generator(bytes_to_pad)
    return padding + string


def ab_unpad(string, plaintext_size):
    """AgileBits custom unpad a string with the given known plaintext size

    Arguments:
        string - The string to unpad
        plaintext_size - The target length in bytes
    """
    return string[len(string)-plaintext_size:]
