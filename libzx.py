#!/usr/bin/env python3
# coding=utf-8
# date 2021-08-03 20:21:36
# https://github.com/calllivecn/tar.py

# 定义格式

"""
原始设计
1. 需要能流式操作。

version: 2B 当前固定为：0x0001
magic nmuber: 2B -- b"zx"
file type: 0x01 --> 普通文件，0x02 --> 目录， 0x03 --> 软链接文件。
filename length: 2B int, # 文件名编码固定为utf-8； 
filesize length: 16B int
filename context:
file context:

如果 file type: 0x03, file context: 就是linkpath, utf-8 编码．


第二次设计，想丰富点
head_size: 7bit chain
magic number: 15B
CRC32: 4B # 计算前以0x00填充。
version: 7bit chain 
file_attributetype_size: 7bit chain, 当前只需1字节
file_attributes_len: 使用可变长度, 7bit链方式保存. 文件的所有属性的长度.

# 这里每个属性前都有一个 "7bit chain 的文件属性类型; FAType, 为一个小tag: |FAType|<可选项: FAType_len|[可选项: content]>|"
FAType: 7bit chain
filename_len: 使用可变长度, 7bit链方式保存. 表示文件名长度。 后面紧跟文件名的UTF-8编码的文件名
filename_utf-8: 

FAType:
file_size: 7bit chain.

uid: 7bit chain.
gid: 7bit chain.

# 现在 linux 好像不需要保存设备文件了。
# devmajor: 7bit chain.
# devminor: 7bit chain.
# uname_len: 7bit chain.
# uname_utf-8:
# gname_len: 7bit chain.
# gname_utf-8:

permission: 7bit chain. 当前是4B; os.stat(filename).st_mode; oct() --> '0o100664', bin() --> '0b1000000110110100'
mtime_len: 7bit chain. 当前是25B
mtime: format --> time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(os.path.getmtime(filename)))

Q:怎么防止恶意破坏？(比如，构造一个恶意大文件）

Q1: 恶意路径的防范。
A1:

Q2: 在解码文件名时失败，怎么处理？
A1: 直接跳过,输出提示.
"""


import io
import sys
import enum
import time
import struct
from binascii import crc32
from pathlib import Path


BUFSIZE=(1<<14) # 16K
MAXATTR=(1<<16) # 防止恶意破坏，目前允许不超过64K的属性头大小。

VERSION = 0x0001
MAGIC = bytearray((90, 88, 32, 230, 137, 147, 229, 140, 133, 230, 150, 135, 228, 187, 182)) # 15B
CRC32Padding = b"\0\0\0\0"
Head = struct.Struct("!H2sBH16s")



def time2store(timestamp):
    return time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(timestamp))       


def store2time(timestamp_byte, lenght=25):
    t = time.strptime(timestamp_byte.decode("utf-8"), "%Y-%m-%d %H:%M:%S %z")
    return int(time.strftime("%s", t))


@enum.unique
class FType(enum.IntEnum):
    """
    当前只需使用一个字节表示文件类型
    """
    FILE = enum.auto()
    DIR = enum.auto()
    SYM = enum.auto()
    LNK = enum.auto()
    # 现在linux感觉不需要备份设备文件了。(2021-11)
    # CHR = enum.auto()
    # BLK = enum.auto()
    FIFO = enum.auto()

@enum.unique
class FAttr(enum.IntEnum):
    """
    当前使用一个字节表示文件属性, 
    当该文件类型有对应的属性时，才会保存。
    """
    FILETYPE = enum.auto() # 必须的
    FILENAME = enum.auto() # 必须的
    SIZE = enum.auto()
    SYMLINK = enum.auto()
    HARDLINK = enum.auto()
    UID = enum.auto()
    GID = enum.auto()
    # 这两个也没必要
    # uname = enum.auto()
    # gname = enum.auto()
    PERMISSION = enum.auto()
    MTIME = enum.auto()

class AttrOrder:

    def __init__(self):
        """
        为每种属性实现从attr2byte, byte2attr的方法。
        """
        self.__attr2byte = {}
        self.__byte2attr = {}
    
    def register(self, fattr, func1, func2):
        """
        fattr: FAttr
        func1: 处理 fattr 属性 到 bytes.
        func2: 处理 fattr 从 bytes 到 属性

        func1: func(Path()) --> attr_bytes
        func2: func(fp) --> attr
        """
        self.__attr2byte[fattr] = func1
        self.__byte2attr[fattr] = func2
    
    def attr2bytes(self, fattr, path):
        """
        path: is Path(filename)
        """
        func = self.__attr2byte[fattr]
        return func(path)
        
    def bytes2attr(self, fattr, fp):
        func = self.__attr2byte[fattr]
        return func(fp)
        
class Buffer(bytearray):
    def __init__(self, size=4096):

        super().__init__(size)
        # self._ba = bytearray(size)
        self._mv = memoryview(self)
    
    def __getitem__(self, slice):
        return self._mv[slice]

class HardLink:

    def __init__(self):
        self._inodes = {}
    
    def isexists(self, path):
        stat = path.stat()
        inode = stat.st_ino

        if stat.st_nlink > 1 and inode in self._inodes and path != self._inodes[inode]:
            # 返回硬链接的文件path
            return self._inodes[inode]
        else:
            self._map[inode] = path
            return False

HARDLINKE = HardLink()

# 每种文件类型需要记录那些属性.
FtypeAttrs = {}
FtypeAttrs[FType.FILE] = (FAttr.FILENAME, FAttr.FILETYPE, FAttr.SIZE, FAttr.UID, FAttr.GID, FAttr.PERMISSION, FAttr.MTIME)
FtypeAttrs[FType.DIR] = (FAttr.FILENAME, FAttr.FILETYPE, FAttr.UID, FAttr.GID, FAttr.PERMISSION, FAttr.MTIME)
FtypeAttrs[FType.SYM] = (FAttr.FILENAME, FAttr.FILETYPE, FAttr.SYMLINK, FAttr.UID, FAttr.GID, FAttr.MTIME)
FtypeAttrs[FType.LNK] = (FAttr.FILENAME, FAttr.FILETYPE, FAttr.HARDLINK)
FtypeAttrs[FType.FIFO] = (FAttr.FILENAME, FAttr.FILETYPE, FAttr.PERMISSION, FAttr.UID, FAttr.GID, FAttr.MTIME)

# 为每种属性注册，
AO = AttrOrder()
AO.register(FAttr.FILENAME, func1=)


class ZxInfo:

    __slots__ = (
        "magic",
        "version",
        "ftype_len",
        "name",
        "name_len",
        "filesize",
        "symlink",
        "linkname",
        "dir",
    )

    def __init__(self):

        self.magic = MAGIC
        self.version = VERSION
        self.attributetype_size = max(FAttr)

        self._attrs = {}

        self.buf = Buffer(1<<16) # 64K
        self.offset = 0

    @property
    def name(self):
        return self._name
    
    @name.setter
    def name(self, name):
        if isinstance(name, Path):
            self._name = name
        else:
            self._name = Path(name)
        
        # self.name_bytes = str(self.name).encode("utf8")
        # self.name_len = len(self.name_bytes)

        self._attrs[FAttr.filename] = self._name

    def info(self, pathname):

        stat = pathname.stat()

        if self.name.is_file():

            hl = HARDLINKE.isexists(pathname)
            if  hl is False:
                self._attr[FAttr.filetype] = FType.FILE

                self._attr[FAttr.size] = stat.st_size

            # 说明之前已有相同indoe，说明这个是硬链接文件。
            else:
                self._attr[FAttr.hardlink] = str(self.name)

            self._attr[FAttr.mtime] = time2store(stat.st_mtime)
            self._attr[FAttr.uid] = stat.st_uid
            self._attr[FAttr.gid] = stat.st_gid
            self._attr[FAttr.permission] = stat.st_mode

        elif self.name.is_dir():
            # self.ftype = FType.DIR
            self._attr[FAttr.filetype] = FType.DIR

            self._attr[FAttr.mtime] = time2store(stat.st_mtime)
            self._attr[FAttr.uid] = stat.st_uid
            self._attr[FAttr.gid] = stat.st_gid
            self._attr[FAttr.permission] = stat.st_mode

        elif self.name.is_symlink():
            # self.ftype = FType.SYM
            self._attr[FAttr.filetype] = FType.SYM
            self._attr[FAttr.symlink] = self.name.readlink()
            self._attr[FAttr.uid] = stat.st_uid
            self._attr[FAttr.gid] = stat.st_gid

        elif self.name.is_fifo():
            # self.ftype = FType.FIFO
            self._attr[FAttr.filetype] = FType.FIFO

            self._attr[FAttr.mtime] = time2store(stat.st_mtime)
            self._attr[FAttr.uid] = stat.st_uid
            self._attr[FAttr.gid] = stat.st_gid
            self._attr[FAttr.permission] = stat.st_mode

        else:
            print(f"当前版本不添加此文件类型: {self.name}", file=sys.stderr)


    @property
    def zxarchive(self):
        return self._zxarchive

    @zxarchive.setter
    def zxarchive(self, fp):
        if isinstance(fp, io.BufferedReader):
            self._zxarchive = fp
    

    def zx2buf(self):
        """
        return: ZxInfo 头信息 bytes
        """
        # 把文件属性信息转换为byte
        buf = io.ByteIO()

        for fatype, value  in self._attr:

            # 先写入属性类型
            buf.write(self.number2store(fatype))

            if fatype in (FAttr.filename, FAttr.symlink, FAttr.hardlink):
                value_bytes = value.encode("utf-8")
                buf.write(self.number2store(len(value_bytes)))
                buf.write(value_bytes)

            elif fatype in (FAttr.size, FAttr.uid, FAttr.gid):
                buf.write(self.number2store(value))

            elif fatype in (FAttr.mtime, FAttr.permission):
                buf.write(self.number2store(len(value)))
                buf.write(self.number2store(value))

            else:
                print(f"当前版本不支持的属性类型：FAType: {fatype}")
        
        attrbuf = buf.getvalue()
        buf.seek(0)
        buf.write(self.magic)
        buf.write(b"\0\0\0\0") # CRC32
        buf.write(self.number2store(self.version))
        buf.write(self.number2store(self.attributetype_size))
        buf.write(self.number2store(len(attrbuf)))
        buf.write(attrbuf)

        CRC32 = crc32(buf.getvalue()) & 0xffffffff
        buf.seek(12)
        buf.write(CRC32.to_bytes(4, "big"))

        head_content = buf.getvalue()
        head_size = self.number2store(len(head_content))

        buf.seek(0)
        buf.write(head_size)
        buf.write(head_content)

        return buf.getvalue()

    def buf2zx(self, fp):
        head_size = self.store2number4fp(fp)

        if head_size > MAXATTR: # 64K
            # print(f"需要使用高级选项以支持特大文件头，--long-size-headerinfo")
            print(f"防止恶意文件攻击，文件头信息必须小于64K。")
            sys.exit(1)
        
        s = 0
        while (n := fp.readinto(self.buf[s:])) != 0 and s < head_size:
            s += n

        if s != head_size:
            print(f"文件头信息读取出错.")
            sys.exit(1)

        self.magic = self.buf[:12]
        if self.magic != MAGIC:
            print(f"文件以损坏", file=sys.stderr)
        
        crc32_file = int.from_bytes(self.buf[12:16], "big")
        self.buf[12:16] = CRC32Padding
        self.offset = 16
        crc32_compute = crc32(self.buf[:head_size].tobytes()) & 0xffffffff

        if crc32_compute != crc32_file:
            print(f"文件损坏.", file=sys.stderr)
            sys.exit(1)

        self.version = self.store2number()
        self.attributetype_size = self.store2number(fp)
        self.attributetypes_len  = self.store2number(fp)

        # 读取文件属性
        while self.offset < head_size:
            fatype = self.store2number()

            # 先读入属性类型
            if fatype in (FAttr.filename, FAttr.symlink, FAttr.hardlink):
                name_len = self.number2store()
                self.name = self.buf[self.offset:self.offset+name_len].decode("utf-8")
                self.offset += name_len

            elif fatype in (FAttr.size, FAttr.uid, FAttr.gid):
                buf.write(self.number2store(value))

            elif fatype in (FAttr.mtime, FAttr.permission)
                buf.write(self.number2store(len(value)))
                buf.write(self.number2store(value))

            else:
                print(f"当前版本不支持的属性类型：FAType: {fatype}")
        

    

    def number2store(self, n):
        """
        使用7bit chain 存储。
        """
        store = bytearray()
        while n>0:
            store.append(n & 0x7f) # 取出后7bit
            n>>=7

        store[0] ^= 0x80 # 把最后一个字节的首位bit置1。
        store.reverse()
        return store


    def store2number4fp(self, fp):
        n = 0
        while ((b := fp.read(1)) >> 7) != 1:
            n = (n<<7) + b

        n = (n<<7) + (b ^ 0x80) # 把最后一个字节的首位bit置0。
        return n
    
    def store2number(self):
        n = 0
        while ((b := self.buf[self.offset:self.offset+1]) >> 7) != 1:
            n = (n<<7) + b

        self.offset += 1
        n = (n<<7) + (b ^ 0x80) # 把最后一个字节的首位bit置0。
        return n
    
    

    @classmethod
    def read(cls, fp):
        cls.fp = fp




class ZxArchive:
    
    def __init__(self, archivepath=None, mode="r", fileobj=None):

        self.archivepath
