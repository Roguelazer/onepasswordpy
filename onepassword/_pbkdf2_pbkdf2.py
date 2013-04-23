import Crypto.Hash.SHA
import Crypto.Hash.SHA512
import pbkdf2


def _pbkdf2_pbkdf2(password, salt, length, iterations, digestmodule):
    generator = pbkdf2.PBKDF2(passphrase=password, salt=salt, iterations=iterations, digestmodule=digestmodule)
    return generator.read(length)


def pbkdf2_sha1(password, salt, length, iterations):
    return _pbkdf2_pbkdf2(password, salt, length, iterations, Crypto.Hash.SHA)


def pbkdf2_sha512(password, salt, length, iterations):
    return _pbkdf2_pbkdf2(password, salt, length, iterations, Crypto.Hash.SHA512)
