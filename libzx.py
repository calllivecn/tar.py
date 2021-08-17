#!/usr/bin/env python3
# coding=utf-8
# date 2021-08-03 20:21:36
# https://github.com/calllivecn/tar.py


import sys
import struct
from pathlib import Path

# 定义格式

"""
version: 2B 当前固定为：0x0001
magic nmuber: 2B -- b"zx"
file type: 0x01 --> 普通文件，0x02 --> 目录， 0x03 --> 软链接文件。
filename length: 2B int, # 文件名编码固定为utf-8； 
filesize length: 16B int
filename context:
file context:

如果 file type: 0x03, file context: 就是linkpath, utf-8 编码．
"""

VERSION = 0x0001
MAGIC = b"zx"
Head = struct.Struct("!H2sBH16s")
TYPE_F = 0x01
TYPE_D = 0x02
TYPE_L = 0x03

MiB=(1<<20)

class ZxInfo:

    __slots__ = (
        "version",
        "magic",
        "ftype"
        "name",
        "name_lenght",
        "filesize",
        "linkpath",
    )

    def __init__(self, name):

        self.version = VERSION
        self.magic = MAGIC

        self.linkpath = None

        if isinstance(name, Path):
            self.name = name
        else:
            self.name = Path(name)
        
        self.name_lenght = str(self.name).encode("utf8")

        if self.name.is_file():
            self.ftype = TYPE_F
        elif self.name.is_dir():
            self.ftype = TYPE_D
        elif self.name.is_symlink():
            self.ftype = TYPE_L
            self.linkpath = self.name.readlink()
        else:
            print(f"不是 普通文件，或 目录 或 软链接文件 不添加", file=sys.stderr)
        
        self.filesize = self.filename.stat().st_size
        
    def head2buf(self):
        """
        return: ZxInfo 头信息
        """
        
        buf = Head.pack(self.version, self.magic, self.name_lenght, self.filesize.to_bytes(16, 'big'))

        return buf

    def head4buf(self, buf):
        self.version, self.magic, self.filename_length, self.filesize = Head.unpack(buf)


class ZxArchive:
    
    def __init__(self, archivepath=None, mode="r", fileobj=None):

        self.archivepath
