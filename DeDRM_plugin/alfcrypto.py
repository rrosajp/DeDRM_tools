#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# crypto library mainly by some_updates

# pbkdf2.py pbkdf2 code taken from pbkdf2.py
# pbkdf2.py Copyright © 2004 Matt Johnston <matt @ ucc asn au>
# pbkdf2.py Copyright © 2009 Daniel Holth <dholth@fastmail.fm>
# pbkdf2.py This code may be freely used and modified for any purpose.

import sys, os
import hmac
from struct import pack
import hashlib

# interface to needed routines libalfcrypto
def _load_libalfcrypto():
    import ctypes
    from ctypes import CDLL, byref, POINTER, c_void_p, c_char_p, c_int, c_long, \
        Structure, c_ulong, create_string_buffer, addressof, string_at, cast, sizeof

    pointer_size = ctypes.sizeof(ctypes.c_voidp)
    name_of_lib = None
    if sys.platform.startswith('darwin'):
        name_of_lib = 'libalfcrypto.dylib'
    elif sys.platform.startswith('win'):
        name_of_lib = 'alfcrypto.dll' if pointer_size == 4 else 'alfcrypto64.dll'
    else:
        name_of_lib = 'libalfcrypto32.so' if pointer_size == 4 else 'libalfcrypto64.so'
    # hard code to local location for libalfcrypto
    libalfcrypto = os.path.join(sys.path[0],name_of_lib)
    if not os.path.isfile(libalfcrypto):
        libalfcrypto = os.path.join(sys.path[0], 'lib', name_of_lib)
    if not os.path.isfile(libalfcrypto):
        libalfcrypto = os.path.join('.',name_of_lib)
    if not os.path.isfile(libalfcrypto):
        raise Exception(f'libalfcrypto not found at {libalfcrypto}')

    libalfcrypto = CDLL(libalfcrypto)

    c_char_pp = POINTER(c_char_p)
    c_int_p = POINTER(c_int)


    def F(restype, name, argtypes):
        func = getattr(libalfcrypto, name)
        func.restype = restype
        func.argtypes = argtypes
        return func

    # aes cbc decryption
    #
    # struct aes_key_st {
    # unsigned long rd_key[4 *(AES_MAXNR + 1)];
    # int rounds;
    # };
    #
    # typedef struct aes_key_st AES_KEY;
    #
    # int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
    #
    #
    # void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
    # const unsigned long length, const AES_KEY *key,
    # unsigned char *ivec, const int enc);

    AES_MAXNR = 14

    class AES_KEY(Structure):
        _fields_ = [('rd_key', c_long * (4 * (AES_MAXNR + 1))), ('rounds', c_int)]

    AES_KEY_p = POINTER(AES_KEY)
    AES_cbc_encrypt = F(None, 'AES_cbc_encrypt',[c_char_p, c_char_p, c_ulong, AES_KEY_p, c_char_p, c_int])
    AES_set_decrypt_key = F(c_int, 'AES_set_decrypt_key',[c_char_p, c_int, AES_KEY_p])



    # Pukall 1 Cipher
    # unsigned char *PC1(const unsigned char *key, unsigned int klen, const unsigned char *src,
    #                unsigned char *dest, unsigned int len, int decryption);

    PC1 = F(c_char_p, 'PC1', [c_char_p, c_ulong, c_char_p, c_char_p, c_ulong, c_ulong])

    class TPZ_CTX(Structure):
        _fields_ = [('v', c_long * 2)]

    TPZ_CTX_p = POINTER(TPZ_CTX)
    topazCryptoInit = F(None, 'topazCryptoInit', [TPZ_CTX_p, c_char_p, c_ulong])
    topazCryptoDecrypt = F(None, 'topazCryptoDecrypt', [TPZ_CTX_p, c_char_p, c_char_p, c_ulong])




    class AES_CBC(object):
        def __init__(self):
            self._blocksize = 0
            self._keyctx = None
            self._iv = 0

        def set_decrypt_key(self, userkey, iv):
            self._blocksize = len(userkey)
            if self._blocksize not in [16, 24, 32]:
                raise Exception('AES CBC improper key used')
            keyctx = self._keyctx = AES_KEY()
            self._iv = iv
            rv = AES_set_decrypt_key(userkey, len(userkey) * 8, keyctx)
            if rv < 0:
                raise Exception('Failed to initialize AES CBC key')

        def decrypt(self, data):
            out = create_string_buffer(len(data))
            mutable_iv = create_string_buffer(self._iv, len(self._iv))
            rv = AES_cbc_encrypt(data, out, len(data), self._keyctx, mutable_iv, 0)
            if rv == 0:
                raise Exception('AES CBC decryption failed')
            return out.raw


    class Pukall_Cipher(object):
        def __init__(self):
            self.key = None

        def PC1(self, key, src, decryption=True):
            self.key = key
            out = create_string_buffer(len(src))
            de = 0
            if decryption:
                de = 1
            rv = PC1(key, len(key), src, out, len(src), de)
            return out.raw



    class Topaz_Cipher(object):
        def __init__(self):
            self._ctx = None

        def ctx_init(self, key):
            tpz_ctx = self._ctx = TPZ_CTX()
            topazCryptoInit(tpz_ctx, key, len(key))
            return tpz_ctx

        def decrypt(self, data,  ctx=None):
            if ctx is None:
                ctx = self._ctx
            out = create_string_buffer(len(data))
            topazCryptoDecrypt(ctx, data, out, len(data))
            return out.raw


    print("Using Library AlfCrypto DLL/DYLIB/SO")
    return (AES_CBC, Pukall_Cipher, Topaz_Cipher)


def _load_python_alfcrypto():

    import aescbc



    class Pukall_Cipher(object):
        def __init__(self):
            self.key = None

        def PC1(self, key, src, decryption=True):
            sum1 = 0;
            sum2 = 0;
            keyXorVal = 0;
            if len(key)!=16:
                raise Exception('Pukall_Cipher: Bad key length.')
            wkey = [ord(key[i*2])<<8 | ord(key[i*2+1]) for i in range(8)]
            dst = ""
            for i in range(len(src)):
                temp1 = 0;
                byteXorVal = 0;
                for j in range(8):
                    temp1 ^= wkey[j]
                    sum2  = (sum2+j)*20021 + sum1
                    sum1  = (temp1*346)&0xFFFF
                    sum2  = (sum2+sum1)&0xFFFF
                    temp1 = (temp1*20021+1)&0xFFFF
                    byteXorVal ^= temp1 ^ sum2
                curByte = ord(src[i])
                if not decryption:
                    keyXorVal = curByte * 257;
                curByte = ((curByte ^ (byteXorVal >> 8)) ^ byteXorVal) & 0xFF
                if decryption:
                    keyXorVal = curByte * 257;
                for j in range(8):
                    wkey[j] ^= keyXorVal;
                dst+=chr(curByte)
            return dst




    class Topaz_Cipher(object):
        def __init__(self):
            self._ctx = None

        def ctx_init(self, key):
            ctx1 = 0x0CAFFE19E
            if isinstance(key, str):
                key = key.encode('latin-1')
            for keyByte in key:
                ctx2 = ctx1
                ctx1 = ((((ctx1 >>2) * (ctx1 >>7))&0xFFFFFFFF) ^ (keyByte * keyByte * 0x0F902007)& 0xFFFFFFFF )
            self._ctx = [ctx1, ctx2]
            return [ctx1,ctx2]

        def decrypt(self, data,  ctx=None):
            if ctx is None:
                ctx = self._ctx
            ctx1 = ctx[0]
            ctx2 = ctx[1]
            plainText = ""
            if isinstance(data, str):
                data = data.encode('latin-1')
            for dataByte in data:
                m = (dataByte ^ ((ctx1 >> 3) &0xFF) ^ ((ctx2<<3) & 0xFF)) &0xFF
                ctx2 = ctx1
                ctx1 = (((ctx1 >> 2) * (ctx1 >> 7)) &0xFFFFFFFF) ^((m * m * 0x0F902007) &0xFFFFFFFF)
                plainText += chr(m)
            return plainText




    class AES_CBC(object):
        def __init__(self):
            self._key = None
            self._iv = None
            self.aes = None

        def set_decrypt_key(self, userkey, iv):
            self._key = userkey
            self._iv = iv
            self.aes = aescbc.AES_CBC(userkey, aescbc.noPadding(), len(userkey))

        def decrypt(self, data):
            iv = self._iv
            return self.aes.decrypt(iv + data)


    print("Using Library AlfCrypto Python")
    return (AES_CBC, Pukall_Cipher, Topaz_Cipher)


def _load_crypto():
    AES_CBC = Pukall_Cipher = Topaz_Cipher = None
    cryptolist = (_load_libalfcrypto, _load_python_alfcrypto)
    for loader in cryptolist:
        try:
            AES_CBC, Pukall_Cipher, Topaz_Cipher = loader()
            break
        except Exception:
            pass
    return AES_CBC, Pukall_Cipher, Topaz_Cipher

AES_CBC, Pukall_Cipher, Topaz_Cipher = _load_crypto()


class KeyIVGen(object):
    # this only exists in openssl so we will use pure python implementation instead
    # PKCS5_PBKDF2_HMAC_SHA1 = F(c_int, 'PKCS5_PBKDF2_HMAC_SHA1',
    #                             [c_char_p, c_ulong, c_char_p, c_ulong, c_ulong, c_ulong, c_char_p])
    def pbkdf2(self, passwd, salt, iter, keylen):

        def xorbytes( a, b ):
            if len(a) != len(b):
                raise Exception("xorbytes(): lengths differ")
            return bytes(x ^ y for x, y in zip(a, b))

        def prf( h, data ):
            hm = h.copy()
            hm.update( data )
            return hm.digest()

        def pbkdf2_F( h, salt, itercount, blocknum ):
            U = prf( h, salt + pack('>i',blocknum ) )
            T = U
            for i in range(2, itercount+1):
                U = prf( h, U )
                T = xorbytes( T, U )
            return T

        sha = hashlib.sha1
        digest_size = sha().digest_size
        # l - number of output blocks to produce
        l = keylen // digest_size
        if keylen % digest_size != 0:
            l += 1
        h = hmac.new( passwd, None, sha )
        T = b""
        for i in range(1, l+1):
            T += pbkdf2_F( h, salt, iter, i )
        return T[:keylen]


