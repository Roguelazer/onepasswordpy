import random

def pkcs5_pad(string, block_size=16):
    """PKCS#5 pad the given string to the given block size
    
    Aguments:
        string - the string to pad. should be bytes()
        block_size - the amount to pad to in bytes
    """
    if block_size <= 0:
        raise ValueError("block_size must be a positive integer")
    return string + (block_size - len(string) % block_size) * chr(block_size - len(string) % block_size)


def pkcs5_unpad(string):
    """PKCS#5 unpad the given string"""
    # preserve empty strings
    if not string:
        return string
    amount_of_padding = ord(string[-1])
    return string[:-amount_of_padding]


def random_byte():
    return random.randint(0, 255)


def ab_pad(string, block_size=16, random_generator=random_byte):
    """AgileBits custom pad a string to the given block size

    Arguments:
        string - The string to pad
        block_size - Block size in bytes
        random_generator - A function that returns a random byte
    """
    bytes_to_pad = block_size - (len(string) % block_size)
    padding = ''.join([chr(random_generator()) for _ in range(bytes_to_pad)])
    return padding + string


def ab_unpad(string, plaintext_size):
    """AgileBits custom unpad a string with the given known plaintext size
    
    Arguments:
        string - The string to unpad
        plaintext_size - The target length in bytes
    """
    return string[len(string)-plaintext_size:]
