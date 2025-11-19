#!/usr/bin/env python3
# coding=utf-8
# date 2018-04-08 06:00:42
# date 2025-11-14
# author calllivecn <calllivecn@outlook.com>

import os
import io
import sys
import getpass
import logging
import argparse

from struct import Struct
from pathlib import Path
from binascii import b2a_hex
from hashlib import sha256, pbkdf2_hmac
from contextlib import contextmanager

from typing import (
    cast,
    Protocol,
)

from cryptography.hazmat.primitives.kdf import (
    pbkdf2,
    argon2,
)
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)



VERSION = "v1.5.0"

BLOCK = 1 << 20  # 1M 读取文件块大小


def getlogger(level=logging.INFO):
    fmt = logging.Formatter("%(asctime)s %(filename)s:%(lineno)d %(message)s", datefmt="%Y-%m-%d-%H:%M:%S")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    logger = logging.getLogger("AES")
    logger.setLevel(level)
    logger.addHandler(stream)
    return logger


logger = getlogger()


class PromptTooLong(Exception):
    pass


class ReadWrite(Protocol):
    def read(self, size: int) -> bytes: ...
    def write(self, data: bytes) -> int: ...
    def close(self) -> None: ...

@contextmanager
def open_stream(path: str, mode: str):
    """
    通用打开流：path 为 "-" 时返回标准输入/输出的 buffer，否则打开文件。
    只在实际打开文件时负责关闭流；标准流不关闭。
    """
    if path == "-":
        if "r" in mode:
            yield cast(ReadWrite, sys.stdin.buffer)
        elif "w" in mode:
            yield cast(ReadWrite, sys.stdout.buffer)
        else:
            raise ValueError("unsupported mode for std stream")
    else:
        f = open(path, mode)
        try:
            yield cast(ReadWrite, f)
        finally:
            f.close()

class FileFormat:
    """
    文件格式类，支持流式数据的编码和解码。
    支持: version code: 0x0001, 0x0002

    2025-11-15:
    把file_version, 移到main()逻辑中处理，这里就不处理了。
    """

    HEADER = Struct("!HH16s32s")  # version, prompt_len, iv, salt
    HEADER_not_version = Struct("!H16s32s")

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
            raise PromptTooLong("你给的密码提示信息太长。(需要 <=65535字节 或 <=21845中文字符)")
        self.prompt = prompt
        self.prompt_len = len(prompt)

    def write_to_stream(self, stream: ReadWrite):
        """
        将文件头写入流中。
        """
        header = self.HEADER.pack(
            self.version,
            self.prompt_len,
            self.iv,
            self.salt
        )
        stream.write(header)
        stream.write(self.prompt)

    @classmethod
    def read_from_stream(cls, stream: ReadWrite, version: int):
        """
        从流中读取文件头并返回 FileFormat 实例。
        """
        header_size = cls.HEADER_not_version.size # 减去 file_version 的 2 字节
        header_data = stream.read(header_size)
        if len(header_data) < header_size:
            raise ValueError("文件头数据不足，无法解析。")

        prompt_len, iv, salt = cls.HEADER_not_version.unpack(header_data)
        prompt = stream.read(prompt_len)
        if len(prompt) < prompt_len:
            raise ValueError("密码提示信息数据不足，无法解析。")

        instance = cls(version)
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
        t = []
        t.append(f"File Version: {hex(self.version)}")
        t.append(f"IV: {b2a_hex(self.iv).decode()}")
        t.append(f"Salt: {b2a_hex(self.salt).decode()}")
        t.append(f"Password Prompt: {self.prompt.decode('utf-8')}")

        return "\n".join(t)



class FileFormat0x3:

    """
    2025-11-15:
    把file_version, 移到main()逻辑中处理，这里就不处理了。
    """

    HEADER = Struct("!HHI")
    HEADER_not_version = Struct("!HI")

    def __init__(self, file_version=0x0003):
        self.version = file_version
        self.prompt_len = 0
        self.aesgcm_chunk = 0 # 2^31 -1 最大明文长度
        self.prompt = b""

    def set_prompt(self, prompt=""):
        """
        设置密码提示信息。
        """
        prompt = prompt.encode("utf-8")
        if len(prompt) > 65535:
            raise PromptTooLong("你给的密码提示信息太长。(需要 <=65535字节 或 <=21845中文字符)")
        self.prompt = prompt
        self.prompt_len = len(prompt)

    def write_to_stream(self, chunk: int, stream: ReadWrite):
        """
        将文件头写入流中。
        """
        self.aesgcm_chunk = chunk
        header = self.HEADER.pack(
            self.version,
            self.prompt_len,
            self.aesgcm_chunk,
        )
        stream.write(header)
        stream.write(self.prompt)

    @classmethod
    def read_from_stream(cls, stream: ReadWrite, version: int):
        """
        从流中读取文件头并返回 FileFormat 实例。
        """
        header_size = cls.HEADER_not_version.size # 减去 file_version 的 2 字节
        header_data = stream.read(header_size)
        if len(header_data) < header_size:
            raise ValueError("文件头数据不足，无法解析。")

        prompt_len, aesgcm_chunk = cls.HEADER_not_version.unpack(header_data)
        prompt = stream.read(prompt_len)
        if len(prompt) < prompt_len:
            raise ValueError("密码提示信息数据不足，无法解析。")

        instance = cls(version)
        instance.prompt_len = prompt_len
        instance.aesgcm_chunk = aesgcm_chunk
        instance.prompt = prompt

        return instance

    def __repr__(self):
        return (
            f"FileFormat(version={self.version}, prompt_len={self.prompt_len}, "
            f"prompt={self.prompt.decode('utf-8')})"
        )
    
    def __str__(self):
        t = []
        t.append(f"File Version: {hex(self.version)}")
        t.append(f"Chunk Size: {self.aesgcm_chunk}")
        t.append(f"Password Prompt: {self.prompt.decode('utf-8')}")
        return "\n".join(t)


def fileinfo0x1_0x2(r: ReadWrite, version: int):
    """
    读取并打印文件的头部信息。
    """
    try:
        header = FileFormat.read_from_stream(r, version)
        print(header)
    except ValueError as e:
        logger.error(f"无法解析文件头：{e}")
        raise e
    except Exception as e:
        logger.error(f"读取文件信息时发生错误：{e}")
        raise e


def fileinfo0x3(r: ReadWrite, version: int):
    """
    读取并打印文件的头部信息。
    """
    try:
        header = FileFormat0x3.read_from_stream(r, version)
        print(header)
    except ValueError as e:
        logger.error(f"无法解析文件头：{e}")
        raise e
    except Exception as e:
        logger.error(f"读取文件信息时发生错误：{e}")
        raise e


def fileinfo(filename: Path|str):

    try:
        # 读取文件头的 version 字段，决定使用哪个 FileFormat 类来解析
        with open(filename, "rb") as fp:
            header_data = fp.read(2)  # 读取 version 字段 (2 字节)
            if len(header_data) < 2:
                raise ValueError("文件头数据不足，无法解析。")
            
            version = Struct("!H").unpack(header_data)[0]

            if version in (0x0001, 0x0002):
                fileinfo0x1_0x2(cast(ReadWrite, fp), version)
            elif version == 0x0003:
                fileinfo0x3(cast(ReadWrite, fp), version)
            else:
                logger.error(f"不支持的文件版本：{hex(version)}")

    except FileNotFoundError as e:
        logger.error(f"文件未找到：{filename}")
        raise e



class AESCrypto:
    """
    AES 加密/解密类，支持流式数据处理。
    """

    def __init__(self, key: bytes):

        self.key = key

        # 0x01, 0x02的加密，只为兼容性测试保留.
        self.header = FileFormat()

    def _derive_key(self, salt: bytes) -> bytes:
        """
        现在 v1.2 (version code: 0x02)使用密钥派生。date: 2021-11-07
        使用 PBKDF2 派生密钥。修改时间：2025-04-24
        """
        return pbkdf2_hmac("sha256", self.key, salt, 200000)

    def _legacy_key(self, salt: bytes) -> bytes:
        """
        旧版本的密钥派生方式。
        现在 v1.0 (version code: 0x01)使用密钥派生。
        """
        return sha256(salt + self.key).digest()

    def encrypt(self, in_stream: ReadWrite, out_stream: ReadWrite, prompt=None):
        """
        加密数据流。
        0x01, 0x02的加密，只为兼容性测试保留.
        """
        # 创建文件头
        self.header.set_prompt(prompt or "")
        self.header.write_to_stream(out_stream)

        # 派生密钥
        if self.header.version == 0x02:
            self.derive_key = self._derive_key(self.header.salt)
        elif self.header.version == 0x01:
            self.derive_key = self._legacy_key(self.header.salt)
        
        # 初始化 AES 加密器
        cipher = Cipher(algorithms.AES(self.derive_key), modes.CFB(self.header.iv))
        aes = cipher.encryptor()

        # 加密数据块
        while (data := in_stream.read(BLOCK)) != b"":
            out_stream.write(aes.update(data))
        out_stream.write(aes.finalize())

    def decrypt(self, in_stream: ReadWrite, out_stream: ReadWrite, version: int):
        """
        解密数据流。
        """
        # 读取文件头
        header = FileFormat.read_from_stream(in_stream, version)

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


class AESGCMFormat:

    HEADER = Struct("!16s16s8s16s16s")

    def __init__(self):
        self.argon2id_salt = os.urandom(16)
        self.argon2id_ad = os.urandom(16)

        # 后32bit使用 每个chunk自增1
        self.nonce_prefix8 = os.urandom(8)
        self.aad = os.urandom(16)
        self.tag = bytes(16)

    def write_to_stream(self, stream: ReadWrite):
        """
        将文件头写入流中。
        """
        header = self.HEADER.pack(
            self.argon2id_salt,
            self.argon2id_ad,
            self.nonce_prefix8,
            self.aad,
            self.tag
        )
        stream.write(header)
    
    @classmethod
    def read_from_stream(cls, stream: ReadWrite):
        """
        从流中读取文件头并返回 Format 实例。
        """
        header_size = cls.HEADER.size
        header_data = stream.read(header_size)
        if len(header_data) < header_size:
            raise ValueError("文件头数据不足，无法解析。")

        argon2id_salt, argon2id_ad, nonce_prefix8, add, tag = cls.HEADER.unpack(header_data)

        instance = cls()
        instance.argon2id_salt = argon2id_salt
        instance.argon2id_ad = argon2id_ad
        instance.nonce_prefix8 = nonce_prefix8
        instance.aad = add
        instance.tag = tag

        return instance

class AESGCM:
    """
    派生的单个密钥可以加密的数据量(实际工程考虑)：
    (1<<30) * (1<<32) = 4EB(1<<50)
    工程取值(1<<30): 是每个 nonce 可以加密的最大明文长度(理论值 2^31 -1)
    (1<<32): 是 AES-GCM 在一个密钥下使用 nonce 加密的最大明文长度。(理论值 2^96)
    每一个新的 chunk，都使用新的 nonce (nonce 的后32bit自增1)
    """

    # 计算最大明文长度 (2^31 - 1 字节), 就是 chunk 的最大值。
    MAX_PLAINTEXT_SIZE = 1<<31 - 1
    NONCE_SUFFX4 = Struct("!I")  # nonce 后4字节
    
    def __init__(self, key: bytes, chunk_size: int):
        self.key = key

        self.set_chunk_size(chunk_size)

        self.chunk_index = 0
        self.nonce_b = b""
    
    
    def set_chunk_size(self, chunk_size: int):
        if chunk_size <= 0 or chunk_size > self.MAX_PLAINTEXT_SIZE:
            raise ValueError(f"chunk size 必须在 2 ~ {self.MAX_PLAINTEXT_SIZE} 之间")
        self.chunk_size = chunk_size


    def key_Argon2id(self, salt: bytes, ad: bytes) -> bytes:
        """
        v1.3 (version code: 0x0003) date: 2025-11-14
        leans: 并行度(使用几个线程)
        memory_cost: KB 65536KB = 64 MB, 要使用的内存量，单位为千字节 (kib)。1 千字节 (KiB) 等于 1024 字节。这必须至少为 8 * lanes
        参考: https://cryptography.io/en/latest/hazmat/primitives/kdf/
        """
        kdf = argon2.Argon2id(salt=salt, length=32, iterations=13, lanes=4, memory_cost=64 * 1024, ad=ad, secret=None)
        return kdf.derive(self.key)
    
    def next_nonce(self, prefix8: bytes) -> bool:
        """
        计算 nonce。
        return: True, 需要更新 key; False, 不需要更新 key
        """
        self.nonce_b = prefix8 + self.NONCE_SUFFX4.pack(self.chunk_index)
        self.chunk_index = (self.chunk_index + 1) & 0xFFFFFFFF  # 保持在 32bit 范围内
        rolled_over = (self.chunk_index == 0)
        return rolled_over


    def encrypt(self, in_stream: ReadWrite, out_stream: ReadWrite, prompt=None):
        """
        加密数据流。
        """
        # 创建文件头
        header = FileFormat0x3()
        header.set_prompt(prompt or "")
        header.write_to_stream(self.chunk_size, out_stream)

        # 读取 AESGCM 文件头
        aesgcm_header = AESGCMFormat()
        aesgcm_header.write_to_stream(out_stream)

        # 派生密钥
        key = self.key_Argon2id(aesgcm_header.argon2id_salt, aesgcm_header.argon2id_ad)


        # 加密数据块
        while (data := self.__read_encrypt(in_stream)) != b"":

            # 计算 nonce
            if self.next_nonce(aesgcm_header.nonce_prefix8):
                # 超过 nonce 使用限制，重新派生密钥
                aesgcm_header = AESGCMFormat()
                aesgcm_header.write_to_stream(out_stream)
                key = self.key_Argon2id(aesgcm_header.argon2id_salt, aesgcm_header.argon2id_ad)

                self.next_nonce(aesgcm_header.nonce_prefix8)  # 重新开始计数


            # 初始化 AES-GCM 加密器
            cipher = Cipher(algorithms.AES(key), modes.GCM(self.nonce_b))
            encryptor = cipher.encryptor()
            encryptor.authenticate_additional_data(aesgcm_header.aad)

            ct = encryptor.update(data) + encryptor.finalize()

            # tag 需要写入到每个加密块前面
            out_stream.write(encryptor.tag)
            out_stream.write(ct)

    def decrypt(self, in_stream: ReadWrite, out_stream: ReadWrite, version: int):
        """
        解密 AES-GCM 流。与 encrypt 对称：先读 FileFormat0x3 header，再读 AESGCMFormat，
        每个块先读 16 字节 tag 再读 ciphertext，按照相同的 nonce 计数派生 key。
        """
        # 读取文件头（包含 chunk-size）
        ff3 = FileFormat0x3.read_from_stream(in_stream, version)
        self.set_chunk_size(ff3.aesgcm_chunk)

        # 读取首个 AESGCM 格式头并派生 key
        aesgcm_header = AESGCMFormat.read_from_stream(in_stream)
        key = self.key_Argon2id(aesgcm_header.argon2id_salt, aesgcm_header.argon2id_ad)

        # 按块读取（每块为 tag(16) + ciphertext(chunk_size)）
        while (data := self.__read_decrypt(in_stream)) != b"":
            # 如果计数回绕，文件中会有新的 AESGCM header，需要读取并重新派生 key
            if self.next_nonce(aesgcm_header.nonce_prefix8):
                aesgcm_header = AESGCMFormat.read_from_stream(in_stream)
                key = self.key_Argon2id(aesgcm_header.argon2id_salt, aesgcm_header.argon2id_ad)
                # 重新开始本块的 nonce 计数
                self.next_nonce(aesgcm_header.nonce_prefix8)

            # data: memoryview(tag + ciphertext)
            if len(data) < 16:
                raise ValueError("加密块数据太短，无法解析 tag。")

            tag = bytes(data[:16])
            ct = data[16:]

            # 使用带 tag 的 GCM 模式解密
            cipher = Cipher(algorithms.AES(key), modes.GCM(self.nonce_b, tag))
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(aesgcm_header.aad)

            pt = decryptor.update(ct) + decryptor.finalize()
            out_stream.write(pt)


    def __read_encrypt(self, in_stream: ReadWrite) -> memoryview:
        """
        读取一个明文块。
        """
        return self.__read(in_stream, self.chunk_size)


    def __read_decrypt(self, in_stream: ReadWrite) -> bytes:
        """
        读取一个加密块 (ciphertext + tag)。
        """
        chunk_tag = self.chunk_size + 16  # AES-GCM 标签大小为 16 字节
        return self.__read(in_stream, chunk_tag)


    def __read(self, in_stream: ReadWrite, size: int) -> memoryview:
        """
        读取指定大小的数据。
        """
        data = io.BytesIO()
        while data.tell() < size:
            chunk = in_stream.read(size - data.tell())
            if not chunk:
                break
            data.write(chunk)
        
        return data.getbuffer()


###################
#
# argparse 类型检查函数
#
####################

def isregulerfile(filename: str) -> Path|str:
    if filename == "-":
        return "-"

    f = Path(filename)
    if f.is_file():
        return f
    else:
        raise argparse.ArgumentTypeError("is not a reguler file")


def notexists(filename: str) -> Path|str:
    if filename == "-":
        return "-"
    
    f = Path(filename)
    
    if f.exists():
        raise argparse.ArgumentTypeError(f"already file {filename}")
    else:
        return f


def isstring(key: str) -> str:
    if isinstance(key, str):
        return key
    else:
        raise argparse.ArgumentTypeError("password require is string")

def check_chunk(n: str) -> int:
    i = int(n)
    if i <= 0 or i > 1024:
        raise argparse.ArgumentTypeError("chunk size must be in 1 ~ 1024 MB")
    return i*(1<< 20)  # 转换为字节数


def main():
    parse = argparse.ArgumentParser(usage="Usage: %(prog)s [-d ] [-p prompt] [-I filename] [-k password] [-v] [-i in_filename|-] [-o out_filename|-]",
                                    description="AES系列算法加密",
                                    epilog=f"""%(prog)s {VERSION} https://github.com/calllivecn/mytools"""
                                    )

    groups = parse.add_mutually_exclusive_group()
    groups.add_argument("-d", action="store_true", help="加密/解密(不指定则为加密)")
    groups.add_argument("-p", action="store", help="提示信息(需要 <=65535字节 或 <=21845中文字符)")
    groups.add_argument("-I", action="store", type=isregulerfile, help="查看文件信息")

    parse.add_argument("-k", action="store", type=isstring, help="密码字符串(如果没有指定本参数，则交互式输入密码)")
    parse.add_argument("--key-count", action="count", help="交互式输入密码次数(默认1次)，使用多密码时起用。")

    parse.add_argument("--chunk", action="store", type=check_chunk, default=(1<<20), help="AES-GCM 加密时使用的 chunk 大小，默认值：1(单位MB, 最大值: 1024)")

    # date: 2023-04-12
    # update: 2025-11-14
    # 提取 keyfile 文件的，从offset 位置开始的1K内容(从offset位置开始必须要有1K的数据, keyfile文件只使用1~3个为好。)
    # 选择keyfile文件时，在有固定头格式的文件时，最好使用offset.
    # 多个 keyfile 时，offset 也需要指定多个。按顺序对应
    parse.add_argument("--keyfile", action="store", nargs="+", type=isregulerfile, help=argparse.SUPPRESS)
    parse.add_argument("--offset", action="store", nargs="+", type=int, default=[0], help=argparse.SUPPRESS)
    parse.add_argument("--keysize", action="store", type=int, default=1024, help=argparse.SUPPRESS)


    parse.add_argument("-v", action="count", help="增加日志输出详细级别，可以使用多个 -v 参数")

    parse.add_argument("-i", action="store", default="-", type=isregulerfile, help="输入文件")
    parse.add_argument("-o", action="store", default="-", type=notexists, help="输出文件")

    parse.add_argument("--parse", action="store_true", help=argparse.SUPPRESS)


    args = parse.parse_args()

    if args.parse:
        print(args)
        sys.exit(0)

    if args.I:
        fileinfo(args.I)
        sys.exit(0)

    if args.v == 1:
        logger.setLevel(logging.INFO)
    elif args.v == 2:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    """
    使用密码或者 keyfile 进行加密/解密。
    keyfile 可以指定多个，每个 keyfile 读取指定offset 之后的 1K 内容作为密钥的一部分。
    """
    if args.k is None and not args.keyfile:

        if args.d is True:
            password = getpass.getpass("Password:")
        else:
            password = getpass.getpass("Password:")
            password2 = getpass.getpass("Password(again):")
            if password != password2:
                logger.info("password mismatches.")
                sys.exit(2)
            
        key = password.encode("utf-8")
    
    elif args.k is not None:
        key = args.k.encode("utf-8")

    elif args.keyfile:

        # keyfile， offset, keysize 参数必须是一样多
        if len(args.keyfile or []) != len(args.offset or []):
            print("keyfile, offset 参数必须是一样多")
            sys.exit(3) 

        keyfiles = []
        file: Path
        for i, file in enumerate(args.keyfile):
            # keyfile 需要大于 1k
            if (file.stat().st_size - args.offset[i]) < args.keysize:
                print("密钥文件 (keyfile) 在偏移量 (offset) 之后需要大于或等于 keysize 大小")
                sys.exit(3)

            with open(file, "rb") as f:
                f.seek(args.offset[i], os.SEEK_SET)
                keyfiles.append(f.read(args.keysize))
        
        key = b"".join(keyfiles)
    
    else:
        logger.error("无法获取加密/解密密钥。")
        sys.exit(2)


    with open_stream(args.i, "rb") as in_stream, open_stream(args.o, "wb") as out_stream:


        if args.d:

            data = in_stream.read(2)
            if len(data) < 2:
                logger.error("无法读取文件版本信息。或者文件版本信息错误。")
                sys.exit(2)

            file_version  = Struct("!H").unpack(data)[0]
            logger.debug(f"文件版本: {hex(file_version)}")
        
            if file_version == 0x0003:
                logger.debug("使用 AES-GCM 格式进行加密/解密。")
                crypto = AESGCM(key, chunk_size=args.chunk)

            elif file_version in (0x0001, 0x0002):
                logger.debug("使用 AES-CFB 格式进行加密/解密。")
                crypto = AESCrypto(key)

            else:
                logger.error("不支持的文件版本。或者文件版本信息错误。")
                sys.exit(2)
            crypto.decrypt(in_stream, out_stream, file_version)

        else:

            crypto = AESGCM(key, chunk_size=args.chunk)
            crypto.encrypt(in_stream, out_stream, args.p)


if __name__ == "__main__":
    main()
