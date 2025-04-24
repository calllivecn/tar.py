#!/usr/bin/env python3
# coding=utf-8
# date 2018-04-08 06:00:42
# author calllivecn <calllivecn@outlook.com>

import os
import io
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

logger = logging.getLogger("AES")

class PromptTooLong(Exception):
    pass


class FileFormat:
    """
    文件格式类，支持流式数据的编码和解码。
    """

    HEADER_STRUCT = Struct("!HH16s32s")  # version, prompt_len, iv, salt

    def __init__(self, file_version=0x0002):
        self.version = file_version
        self.prompt_len = 0
        self.iv = os.urandom(16)
        self.salt = os.urandom(32)
        self.prompt = b""

    def set_prompt(self, prompt=""):
        """
        设置密码提示信息。
        """
        prompt = prompt.encode("utf-8")
        if len(prompt) > 65535:
            raise ValueError("密码提示信息太长，必须小于 65535 字节。")
        self.prompt = prompt
        self.prompt_len = len(prompt)

    def encode(self):
        """
        将文件头编码为二进制数据。
        """
        header = self.HEADER_STRUCT.pack(
            self.version,
            self.prompt_len,
            self.iv,
            self.salt
        )
        return header + self.prompt

    @classmethod
    def decode(cls, data):
        """
        从二进制数据解码为 FileFormat 实例。
        """
        header_size = cls.HEADER_STRUCT.size
        header_data = data[:header_size]
        prompt_data = data[header_size:]

        version, prompt_len, iv, salt = cls.HEADER_STRUCT.unpack(header_data)
        prompt = prompt_data[:prompt_len].decode("utf-8")

        instance = cls(file_version=version)
        instance.iv = iv
        instance.salt = salt
        instance.prompt = prompt.encode("utf-8")
        instance.prompt_len = prompt_len

        return instance

    def write_to_stream(self, stream: io.BufferedWriter):
        """
        将文件头写入流中。
        """
        header = self.HEADER_STRUCT.pack(
            self.version,
            self.prompt_len,
            self.iv,
            self.salt
        )
        stream.write(header)
        stream.write(self.prompt)

    @classmethod
    def read_from_stream(cls, stream: io.BufferedReader):
        """
        从流中读取文件头并返回 FileFormat 实例。
        """
        header_size = cls.HEADER_STRUCT.size
        header_data = stream.read(header_size)
        if len(header_data) < header_size:
            raise ValueError("文件头数据不足，无法解析。")

        version, prompt_len, iv, salt = cls.HEADER_STRUCT.unpack(header_data)
        prompt = stream.read(prompt_len)
        if len(prompt) < prompt_len:
            raise ValueError("密码提示信息数据不足，无法解析。")

        instance = cls(file_version=version)
        instance.iv = iv
        instance.salt = salt
        instance.prompt = prompt
        instance.prompt_len = prompt_len

        return instance

    def __repr__(self):
        return (
            f"FileFormat(version={self.version}, prompt_len={self.prompt_len}, "
            f"iv={self.iv.hex()}, salt={self.salt.hex()}, prompt={self.prompt.decode('utf-8')})"
        )
    
    def __str__(self):
        return self.__repr__()



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


def fileinfo(filename):
    """
    读取并打印文件的头部信息。
    """
    try:
        with open(filename, "rb") as fp:
            # 使用 FileFormat 类解析文件头
            header = FileFormat.read_from_stream(fp)

        # 打印文件头信息
        print(f"File Version: {hex(header.version)}")
        print(f"IV: {b2a_hex(header.iv).decode()}")
        print(f"Salt: {b2a_hex(header.salt).decode()}")
        print(f"Password Prompt: {header.prompt.decode('utf-8')}")

    except ValueError as e:
        logger.error(f"无法解析文件头：{e}")
        raise e
    except FileNotFoundError:
        logger.error(f"文件未找到：{filename}")
        raise e
    except Exception as e:
        logger.error(f"读取文件信息时发生错误：{e}")
        raise e


class AESCrypto:
    """
    AES 加密/解密类，支持流式数据处理。
    """

    def __init__(self, password: str):
        self.password = password

    def _derive_key(self, salt):
        """
        现在 v1.2 (version code: 0x02)使用密钥派生。date: 2021-11-07
        使用 PBKDF2 派生密钥。修改时间：2025-04-24
        """
        return pbkdf2_hmac("sha256", self.password.encode("utf-8"), salt, 200000)

    def _legacy_key(self, salt):
        """
        旧版本的密钥派生方式。
        """
        return sha256(salt + self.password.encode("utf-8")).digest()

    def encrypt(self, in_stream: io.BufferedReader, out_stream: io.BufferedWriter, prompt=None):
        """
        加密数据流。
        """
        # 创建文件头
        header = FileFormat()
        header.set_prompt(prompt or "")
        header.write_to_stream(out_stream)

        # 派生密钥
        key = self._derive_key(header.salt)

        # 初始化 AES 加密器
        cipher = Cipher(algorithms.AES(key), modes.CFB(header.iv))
        aes = cipher.encryptor()

        # 加密数据块
        while (data := in_stream.read(BLOCK)) != b"":
            out_stream.write(aes.update(data))
        out_stream.write(aes.finalize())

    def decrypt(self, in_stream: io.BufferedReader, out_stream: io.BufferedWriter):
        """
        解密数据流。
        """
        # 读取文件头
        header = FileFormat.read_from_stream(in_stream)

        # 根据文件版本派生密钥
        if header.version == 0x02:
            key = self._derive_key(header.salt)
        elif header.version == 0x01:
            key = self._legacy_key(header.salt)
        else:
            logger.error(f"不支持的文件版本：{header.version}")
            sys.exit(2)

        # 初始化 AES 解密器
        cipher = Cipher(algorithms.AES(key), modes.CFB(header.iv))
        aes = cipher.decryptor()

        # 解密数据块
        while (data := in_stream.read(BLOCK)) != b"":
            out_stream.write(aes.update(data))
        out_stream.write(aes.finalize())


def main():
    parse = argparse.ArgumentParser(
        usage="Usage: %(prog)s [-d ] [-p prompt] [-I filename] [-k password] [-v] [-i in_filename|-] [-o out_filename|-]",
        description="AES 加密",
        epilog=f"%(prog)s {version}\nhttps://github.com/calllivecn/mytools"
    )

    groups = parse.add_mutually_exclusive_group()
    groups.add_argument("-d", action="store_false", help="decrypto (default: encrypto)")
    groups.add_argument("-p", action="store", help="password prompt")
    groups.add_argument("-I", action="store", type=isregulerfile, help="AES crypto file")

    parse.add_argument("-k", action="store", type=isstring, help="password")
    parse.add_argument("-v", action="count", help="verbose")

    parse.add_argument("-i", action="store", default="-", type=isregulerfile, help="in file")
    parse.add_argument("-o", action="store", default="-", type=notexists, help="out file")

    args = parse.parse_args()

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

    crypto = AESCrypto(password)

    # 加密
    if args.d:
        logger.debug("开始加密...")
        crypto.encrypt(in_stream, out_stream, args.p)
    # 解密
    else:
        logger.debug("开始解密...")
        crypto.decrypt(in_stream, out_stream)

    in_stream.close()
    out_stream.close()

if __name__ == "__main__":
    main()
