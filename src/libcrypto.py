#!/usr/bin/env python3
# coding=utf-8
# date 2018-04-08 06:00:42
# author calllivecn <c-all@qq.com>

import os
import sys
import getpass
import logging
import argparse

from struct import Struct
from binascii import b2a_hex
from os.path import isfile, exists
from hashlib import sha256, pbkdf2_hmac


from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)



ENCRYPTO = 1  # 加密
DECRYPTO = 0  # 解密

version = "v1.2.0"


BLOCK = 1 << 20  # 1M 读取文件块大小

def getlogger(level=logging.INFO):
    fmt = logging.Formatter(
        "%(asctime)s %(filename)s:%(lineno)d %(message)s", datefmt="%Y-%m-%d-%H:%M:%S")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    logger = logging.getLogger("AES")
    logger.setLevel(level)
    logger.addHandler(stream)
    return logger


logger = getlogger()


class PromptTooLong(Exception):
    pass


class FileFormat:
    """
    写入到文件的文件格式
    """

    def __init__(self, file_version=0x0002):
        """
        prompt: `str': 密码提示信息
        out_fp: `fp': 类文件对象
        """

        logger.debug("file header format build")
        self.version = file_version  # 2byte
        self.prompt_len = bytes(2)  # 2bytes 提示信息字节长度
        self.iv = os.urandom(16)     # 16byte
        self.salt = os.urandom(32)   # 32byte
        # self.long = bytes(8)        # 8byte 加密后数据部分长度
        # self.sha256 = bytes(32)     # 32byte 加密后数据部分校验和
        self.prompt = bytes()        # 定长，utf-8编码串, 之后填写，可为空
        # 以上就格式顺序

        self.file_fmt = Struct("!HH")

    def setPrompt(self, prompt=""):
        logger.debug("set prompt info")
        prompt = prompt.encode("utf-8")
        self.prompt_len = len(prompt)

        if self.prompt_len > 65536:
            raise PromptTooLong("你给的密码提示信息太长。(需要 <=65536字节 或 <=21845中文字符)")
        else:
            self.prompt = prompt

    def setHeader(self, fp):
        # logger.debug(f"set file header {fp.name}")
        logger.debug(f"set file header")
        logger.debug(f"\nversion: {self.version}\n prompt_len: {self.prompt_len}\n vi: {self.iv}\n salt: {self.salt}\n prompt: {self.prompt}")
        headers = self.file_fmt.pack(self.version, self.prompt_len)
        self.HEAD = headers + self.iv + self.salt + self.prompt
        return fp.write(self.HEAD)

    def getHeader(self, fp):
        logger.debug("get file header")
        file_version, prompt_len = self.file_fmt.unpack(fp.read(4))
        iv = fp.read(16)
        salt = fp.read(32)
        prompt = fp.read(prompt_len)
        logger.debug(f"\nversion: {file_version}\n prompt_len: {prompt_len}\n vi: {iv}\n salt: {salt}\n prompt: {self.prompt}")
        return file_version, prompt_len, iv, salt, prompt.decode("utf-8")


def isregulerfile(filename):
    if isfile(filename) or filename == "-":
        return filename
    else:
        raise argparse.ArgumentTypeError("is not a reguler file")


def notexists(filename):
    if exists(filename) and filename != "-":
        raise argparse.ArgumentTypeError("already file {}".format(filename))
    else:
        return filename


def isstring(key):
    if isinstance(key, str):
        return key
    else:
        raise argparse.ArgumentTypeError("password require is string")


# v1.0 (version code: 0x01) 的做法，密钥没有派生。
def salt_key(password, salt):
    key = sha256(salt + password.encode("utf-8")).digest()
    return key

# 现在 v1.2 (version code: 0x02)使用密钥派生。date: 2021-11-07
def key_deriverd(password, salt):
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)

def fileinfo(filename):
    header = FileFormat()
    with open(filename, "rb") as fp:
        file_version, prompt_len, iv, salt, prompt = header.getHeader(fp)

    print("File Version: {}(1byte)".format(hex(file_version)))

    print("IV: {}".format(b2a_hex(iv).decode()))

    print("Salt: {}".format(b2a_hex(salt).decode()))

    print("Password Prompt: {}".format(prompt))


def encrypt(in_stream, out_stream, password, prompt=None):
    header = FileFormat()

    if prompt is None:
        header.setPrompt()
    else:
        header.setPrompt(prompt)

    header.setHeader(out_stream)

    key = key_deriverd(password, header.salt)

    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.CFB(header.iv))
    aes = cipher.encryptor()

    while (data := in_stream.read(BLOCK)) != b"":
        en_data = aes.update(data)
        out_stream.write(en_data)

    out_stream.write(aes.finalize())


def decrypt(in_stream, out_stream, password):
    header = FileFormat()

    file_version, prompt_len, iv, salt, prompt = header.getHeader(
        in_stream)

    if file_version == 0x02:
        key = key_deriverd(password, salt)
    elif file_version == 0x01:
        key = salt_key(password, salt)
    else:
        logger.error(f"不支持的文件版本。")
        sys.exit(2)

    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.CFB(iv))
    aes = cipher.decryptor()

    while (data := in_stream.read(BLOCK)) != b"":
        de_data = aes.update(data)
        out_stream.write(de_data)
    
    out_stream.write(aes.finalize())



def main():
    parse = argparse.ArgumentParser(usage="Usage: %(prog)s [-d ] [-p prompt] [-I filename] [-k password] [-v] [-i in_filename|-] [-o out_filename|-]",
                                    description="AES 加密",
                                    epilog="""%(prog)s {}
                                    https://github.com/calllivecn/mytools""".format(version)
                                    )

    groups = parse.add_mutually_exclusive_group()
    groups.add_argument("-d", action="store_false",
                        help="decrypto (default: encrypto)")
    groups.add_argument("-p", action="store", help="password prompt")
    groups.add_argument("-I", action="store",
                        type=isregulerfile, help="AES crypto file")

    parse.add_argument("-k", action="store", type=isstring, help="password")
    parse.add_argument("-v", action="count", help="verbose")

    parse.add_argument("-i", action="store", default="-",
                       type=isregulerfile, help="in file")
    parse.add_argument("-o", action="store", default="-",
                       type=notexists, help="out file")

    args = parse.parse_args()
    # print(args);#sys.exit(0)


    if args.I:
        fileinfo(args.I)
        sys.exit(0)

    if args.v == 1:
        logger.setLevel(logging.INFO)
    elif args.v == 2:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.k is None:
        if args.d:
            password = getpass.getpass("Password:")
            password2 = getpass.getpass("Password(again):")
            if password != password2:
                logger.info("password mismatches.")
                sys.exit(2)
        else:
            password = getpass.getpass("Password:")

    else:
        password = args.k

    if args.i == "-":
        in_stream = sys.stdin.buffer
    else:
        in_stream = open(args.i, "rb")

    if args.o == "-":
        out_stream = sys.stdout.buffer
    else:
        out_stream = open(args.o, "wb")
    
    # 加密
    if args.d:

        logger.debug("开始加密...")
        encrypt(in_stream, out_stream, password, args.p)
        in_stream.close()
        out_stream.close()

    # 解密
    else:
        logger.debug("开始解密...")

        decrypt(in_stream, out_stream, password)

        in_stream.close()
        out_stream.close()


if __name__ == "__main__":
    main()
