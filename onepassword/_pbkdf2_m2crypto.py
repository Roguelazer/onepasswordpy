import struct

from Crypto.Util.strxor import strxor
import M2Crypto.EVP

def pbkdf2_sha1(password, salt, length, iterations):
    return M2Crypto.EVP.pbkdf2(password=password, salt=salt, iter=iterations, keylen=length)


def pbkdf2_sha512(password, salt, length, iterations):
    hmac = M2Crypto.EVP.HMAC(key=password, algo='sha512')
    hmac.update(salt)
    generated_data = 0
    generated_chunks = []
    iterator = range(iterations - 1)
    i = 1
    while generated_data < length:
        hmac.reset(key=password)
        hmac.update(salt)
        hmac.update(struct.pack(">I", i))
        U = U_1 = hmac.final()
        for j in iterator:
            hmac.reset(key=password)
            hmac.update(U_1)
            U_1 = t = hmac.final()
            U = strxor(U, t)
        generated_chunks.append(U)
        generated_data += len(U)
        i += 1
    return "".join(generated_chunks)[:length]
