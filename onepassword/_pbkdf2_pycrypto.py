import Crypto.Hash.HMAC
import Crypto.Hash.SHA
import Crypto.Hash.SHA512
import Crypto.Protocol.KDF


def pbkdf2_sha1(password, salt, length, iterations):
    prf = lambda p,s: Crypto.Hash.HMAC.new(p, s, digestmod=Crypto.Hash.SHA).digest()
    return Crypto.Protocol.KDF.PBKDF2(password=password, salt=salt, dkLen=length, count=iterations, prf=prf)


def pbkdf2_sha512(password, salt, length, iterations):
    prf = lambda p,s: Crypto.Hash.HMAC.new(p, s, digestmod=Crypto.Hash.SHA512).digest()
    return Crypto.Protocol.KDF.PBKDF2(password=password, salt=salt, dkLen=length, count=iterations, prf=prf)
