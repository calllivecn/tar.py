#!/usr/bin/env python3
# coding=utf-8
# date 2021-07-01 16:56:27
# https://github.com/calllivecn

"""
1. 需要测试 tarfile.TarInfo 的用法。
2. 在这里把它封装成，一个可以 read() only for stream object, 
    的使用类，需要write() only to stream object.
"""

import time
import stat
from functools import partial

errors = "surrogateescape"

from libtarinfo import (
    TarInfo,
    ENCODING,
    BLOCKSIZE,
    RECORDSIZE,
    NUL,
)


"""
使用tarinfo 类直自己写出
"""

class Tar:

    # 16k
    BUFSIZE = 1<<14

    def __init__(self, fileobj, tarformat):
        self.tarformat = tarformat
        self.fileobj = fileobj

        self.tarinfo = TarInfo()

    def list(self, verbose=False):
        """
        返回tar中的文件列表
        """
        filelist = []

        block = self.__readblock()
        tarinfo = self.tarinfo.frombuf(block, ENCODING, errors)

        for fileinfo in filelist:
            if verbose:
                self.print_verbose(fileinfo)
            else:
                self.print_name(fileinfo)


    def next(self):
        pass
    
    def print_verbose(self, tarinfo):
        # stat.filemode 返回 '?rwxr-xr-x' 这样的串
        permission = stat.filemode(tarinfo.mode)[1:]

        if tarinfo.isfile():
            ftype = '-'
        elif tarinfo.isdir():
            ftype = 'd'
        elif tarinfo.issym():
            ftype = 'l'
        elif tarinfo.islnk():
            ftype = 'h'
        elif tarinfo.ischr():
            ftype = 'c'
        elif tarinfo.isblk():
            ftype = 'b'
        elif tarinfo.isfifo():
            ftype = 'p'
        else:
            ftype = '?'
        
        uname = tarinfo.uname
        gname = tarinfo.gname

        filesize = tarinfo.size

        filetime = "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(time.localtime(tarinfo.mtime)[:6])

        if tarinfo.issym():
            arcname_link = f"{tarinfo.name} --> {tarinfo.linkname}"
        elif tarinfo.islnk():
            arcname_link = f"{tarinfo.name} ==> {tarinfo.linkname}"
        else:
            arcname_link = tarinfo.name

        verbosrformat=f"{ftype}{permission} {uname}/{gname} {filesize:>20d} {filetime} {arcname_link}"

        print(verbosrformat)

    def print_name(self, tarinfo):
        print(tarinfo.name)

    def __readblock(self, blocksize=1):
        block = b""
        data_len = 0

        while data_len < BLOCKSIZE:
            data = self.fileobj.read(BLOCKSIZE)
            if data == b"":
                return b""
            block += data 
            data_len += len(data_len)
        
        if data_len > self.TARBLOCK:
            self.data
        
        return block

    def __write(self, data):
        block = b""
        data_len = len(data)
        n, c = divmod(data_len, self.TARBLOCK)
        if c > 0:
            pass
        while data:
            pass
