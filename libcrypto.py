#!/usr/bin/env python3
# coding=utf-8
# date 2020-04-25 12:38:10
# author calllivecn <c-all@qq.com>


from ctypes import CDLL
from ctypes.util import find_library
from ctypes import (
                    c_char_p, 
                    c_int, 
                    c_long, 
                    byref, 
                    create_string_buffer, 
                    c_void_p
                )

####################################
#
# 加载openssl函数库 begin
#
##################################


ENCRYPT = 1  # 加密
DECRYPT = 0  # 解密


class CryptoError(Exception):
    pass


# 加密类
class Crypto:
    """
    对称加密和解密的流程类似，一般有以下几个步骤：

    1. 生成一个记录加密（解密）上下文信息的EVP_CIPHER_CTX对象
    2. 初始化加密（解密）算法，在这一步指定算法和密钥
    3. 加密（解密）数据
    4. 处理尾部数据，结束加密（解密）
    5. 清空并释放加密（解密）上下文对象，清空其他敏感信息
    其中使用的函数以及其他一些相关函数如下：

    1. 创建新加密上下文EVP_CIPHER_CTX对象, 并将其作为返回值返回:
        EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
    
    2. 清除并释放加密上下文对象(防止数据泄露)，参数为需要释放的EVP_CIPHER_CTX对象，在所有加密操作结束后调用该函数:
        void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)

    3. 目前不是很清楚具体作用，可能是重置一个EVP_CIPHER_CTX对象从而可以循环利用避免不必要的内存释放和分配吧:
        int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx)

    4. 加解密初始化操作

        4.1. 执行加密初始化
        int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv)
        返回值为1表示成功，0表示失败，可以使用上述错误处理中的函数打印错误信息

        参数	描述
        ctx	    加密上下文对象
        type	加密算法类型，在openssl/evp.h中定义了许多以算法命名的函数, 这些函数的返回值作为此参数使用，比如EVP_aes_256_cbc()
        impl	利用硬件加密的接口，本文不讨论，设置为NULL
        key	    用于加密的密钥
        iv	    某些加密模式如cbc需要使用的初始化向量，如果加密模式不需要可以设置为NULL

        4.2. 执行解密初始化
        int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv)
        该函数对解密操作进行初始化，参数与返回值上述加密初始化函数描述相同

    5. 执行加解密操作
        注意, 输出缓冲区的长度需要比输入缓冲区大一个加密块，否则会出现错误。
        注意，如果出现overlap错误，请检查输入和输出缓冲区是否分离，以及是否其长度是否满足第一个注意事项

        5.1. 加密
        int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
        返回值为1表示成功，返回值为0表示失败

        参数	描述
        ctx	    加密上下文对象
        out	    保存输出结果（密文）的缓冲区
        outl	接收输出结果长度的指针
        in	    包含输入数据（明文）的缓冲区
        inl	    输入数据的长度

        5.2. 解密
        int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
        执行解密的函数，参数和返回值和上述加密函数类似，只需要注意输入和输出不要混淆


    6. 加解密尾部数据处理

        6.1. 加密
        int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
        返回值为1表示成功，0表示失败。

        该函数处理加密结果的尾部数据（比如填充段块），还可能输出一些密文数据，参数描述如下：
        参数	描述
        ctx	    加密上下文对象
        out	    保存输出结果（密文）的缓冲区（注意这个指针要指向之前已经保存的加密数据的尾部）
        outl	接收输出结果长度的指针

        6.2. 解密
        int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl)
        该函数处理解密结果的尾部数据，还可能输出一些明文数据，参数和返回值同上述加密尾部数据处理的函数类似，注意这个函数输出的是明文即可

    7. 资源释放
        在加解密操作完成后，对可能的密码缓冲区的清空，以及释放上下文对象，一般使用上下文处理中的
        void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
        
    8. 口令生成密钥(key derivation)
        有时候我们需要使用口令来生成加密密钥，openssl推荐使用PBKDF2算法来进行这个操作，使用到的函数如下。

        int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                   const unsigned char *salt, int saltlen, int iter,
                   const EVP_MD *digest,
                   int keylen, unsigned char *out);
        返回值为1表示成功，0表示失败。

        该函数使用PKKDF2算法利用口令生成指定长度的密钥，其参数描述如下：
            参数	描述
            pass	用于生成密钥的口令
            passlen	口令的长度
            salt	用于生成密钥的盐值(建议4字节以上)，当然也可以设置为NULL表示不使用
            saltlen	盐值的长度，如果不使用则为0
            iter	迭代次数（openssl建议设置到1000以上，用于增加暴力破解的难度）
            digest	单向hash函数，在openssl/evp.h中定义了许多以算法命名的函数, 这些函数的返回值作为此参数使用，比如EVP_sha256()
            keylen	输出的密钥的长度
            out	    保存输出的密钥的缓冲区

    """

    ciphers = {
        'aes-128-cbc': (16, 16),
        'aes-192-cbc': (24, 16),
        'aes-256-cbc': (32, 16),
        'aes-128-cfb': (16, 16),
        'aes-192-cfb': (24, 16),
        'aes-256-cfb': (32, 16),
        'aes-128-ofb': (16, 16),
        'aes-192-ofb': (24, 16),
        'aes-256-ofb': (32, 16),
        'aes-128-ctr': (16, 16),
        'aes-192-ctr': (24, 16),
        'aes-256-ctr': (32, 16),
        'aes-128-cfb8': (16, 16),
        'aes-192-cfb8': (24, 16),
        'aes-256-cfb8': (32, 16),
        'aes-128-cfb1': (16, 16),
        'aes-192-cfb1': (24, 16),
        'aes-256-cfb1': (32, 16),
        'bf-cfb': (16, 8),
        'camellia-128-cfb': (16, 16),
        'camellia-192-cfb': (24, 16),
        'camellia-256-cfb': (32, 16),
        'cast5-cfb': (16, 8),
        'des-cfb': (8, 8),
        'idea-cfb': (16, 8),
        'rc2-cfb': (16, 8),
        'rc4': (16, 0),
        'seed-cfb': (16, 16),
    }

    def __init__(self, cipher_name, key, iv, op=ENCRYPT):

        self._libcrypto = None
        self._loaded = False
        self._buf = b''
        self._buf_size = 8192  # 1<<13, 8k size


        self._ctx = None

        self.op = op # 1: 表示执行加密操作， 0: 表示解密操作。

        if not self._loaded:
            self.__load_openssl()

        cipher = self._libcrypto.EVP_get_cipherbyname(cipher_name.encode("utf-8"))
        if not cipher:
            cipher = self.__load_cipher(cipher_name)
        if not cipher:
            raise CryptoError(f'cipher {cipher_name} not found in libcrypto')

        key_ptr = c_char_p(key)
        iv_ptr = c_char_p(iv)

        self._ctx = self._libcrypto.EVP_CIPHER_CTX_new()

        if not self._ctx:
            raise CryptoError('can not create cipher context')

        if self.op == ENCRYPT:
            r = self._libcrypto.EVP_EncryptInit_ex(self._ctx, cipher, None, key_ptr, iv_ptr)
        else:
            r = self._libcrypto.EVP_DecryptInit_ex(self._ctx, cipher, None, key_ptr, iv_ptr)

        if not r:
            self.__clean()
            raise CryptoError(f"can not initialize {cipher} cipher context")

    def Update(self, data):
        if self.op == 1:
            return self.__EncryptUpdate(data)
        elif self.op == 0:
            return self.__DecryptUpdate(data)

    def __EncryptUpdate(self, data):

        cipher_out_len = c_long(0)
        l = len(data)

        if self._buf_size < l:
            self._buf_size = l * 2
            self._buf = create_string_buffer(self._buf_size)

        self._libcrypto.EVP_EncryptUpdate(self._ctx, byref(self._buf),
                                        byref(cipher_out_len), c_char_p(data), l)

        # self.buf is copied to a str object when we access self.buf.raw
        return self._buf.raw[:cipher_out_len.value]

    def __DecryptUpdate(self, data):
        cipher_out_len = c_long(0)
        l = len(data)

        if self._buf_size < l:
            self._buf_size = l * 2
            self._buf = create_string_buffer(self._buf_size)

        self._libcrypto.EVP_DecryptUpdate(self._ctx, byref(self._buf),
                                        byref(cipher_out_len), c_char_p(data), l)

        return self._buf.raw[:cipher_out_len.value]


    def __load_cipher(self, cipher_name):
        func_name = 'EVP_' + cipher_name.replace('-', '_')
        cipher = getattr(self._libcrypto, func_name, None)
        if cipher:
            cipher.restype = c_void_p
            return cipher()
        return None


    def __load_openssl(self):

        # find library: libcrypto.so
        lib = find_library("crypto")

        if lib:
            self._libcrypto = CDLL(lib)
        else:
            raise CryptoError('libcrypto(OpenSSL) not found')

        self._libcrypto.EVP_get_cipherbyname.restype = c_void_p

        self._libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p

        self._libcrypto.EVP_EncryptInit_ex.argtypes = (c_void_p, c_void_p, c_char_p, c_char_p)

        self._libcrypto.EVP_DecryptInit_ex.argtypes = (c_void_p, c_void_p, c_char_p, c_char_p)

        self._libcrypto.EVP_EncryptUpdate.argtypes = (c_int, )

        self._libcrypto.EVP_DecryptUpdate.argtypes = (c_int, )

        if hasattr(self._libcrypto, "EVP_CIPHER_CTX_cleanup"):
            self._libcrypto.EVP_CIPHER_CTX_cleanup.argtypes = (c_void_p,)
        else:
            self._libcrypto.EVP_CIPHER_CTX_reset.argtypes = (c_void_p,)

        self._libcrypto.EVP_CIPHER_CTX_free.argtypes = (c_void_p,)

        self._libcrypto.RAND_bytes.restype = c_int
        self._libcrypto.RAND_bytes.argtypes = (c_void_p, c_int)

        #if hasattr(self._libcrypto, 'OpenSSL_add_all_ciphers'):
        #    self._libcrypto.OpenSSL_add_all_ciphers()

        self._buf = create_string_buffer(self._buf_size)
        self._loaded = True

    def __del__(self):
        self.__clean()

    def __clean(self):
        if self._ctx:

            if hasattr(self._libcrypto, "EVP_CIPHER_CTX_cleanup"):
                self._libcrypto.EVP_CIPHER_CTX_cleanup(self._ctx)
            else:
                self._libcrypto.EVP_CIPHER_CTX_reset(self._ctx)

            self._libcrypto.EVP_CIPHER_CTX_free(self._ctx)


####################################
#
# 加载openssl函数库 end
#
####################################



def __test():
    import random
    with open("/dev/urandom", "rb") as f:
        data = f.read(random.randint(4, 41))

    print("数据长度：", len(data), "原始数据：", data)

    key = b"123456789abcdef"

    iv = b"fedcba987654321"

    aes1 = Crypto("aes-256-cfb", key, iv, ENCRYPT)

    en_data = aes1.Update(data)

    print("数据长度：", len(data), "加密数据：", en_data)

    aes2 = Crypto("aes-256-cfb", key, iv, DECRYPT)

    de_data = aes2.Update(en_data)

    print("数据长度：", len(data), "解密数据：", de_data)

    # 加密一段随机数据 5M
    data_size = 5*(1<<20)
    chunk = 1<<10

    # 生成原始数据
    c = data_size
    with open("/dev/urandom" ,"rb") as f, open("source_data", "wb") as f2:
        while c > 0:
            f2.write(f.read(chunk))
            c -= chunk
    
    # 加密原始数据
    Encrypt = Crypto("aes-256-cfb", key, iv, ENCRYPT)
    c = data_size
    with open("source_data", "rb") as f, open("encrypt_data", "wb") as f2:
        while c > 0:
            f2.write(Encrypt.Update(f.read(chunk)))
            c -= chunk

    # 解密原始数据
    Decrypt = Crypto("aes-256-cfb", key, iv, DECRYPT)
    c = data_size
    with open("encrypt_data", "rb") as f, open("decrypt_data", "wb") as f2:
        while c > 0:
            f2.write(Decrypt.Update(f.read(chunk)))
            c -= chunk


if __name__ == "__main__":
    __test()
