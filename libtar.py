#!/usr/bin/env python3
# coding=utf-8
# date 2021-07-01 16:56:27
# https://github.com/calllivecn

"""
1. 需要测试 tarfile.TarInfo 的用法。
2. 在这里把它封装成，一个可以 read() only for stream object, 
    的使用类，需要write() only to stream object.
"""

from functools import partial

errors = "surrogateescape"

from libtarinfo import TarInfo


"""
使用tarinfo 类直自己写出
"""

class Tar:

    TARBLOCK = 512
    RECCORDSIZE = TARBLOCK * 20

    # 16k
    BUFSIZE = 1<<14

    def __init__(self, fileobj, tarformat):
        self.tarformat = tarformat
        self.fileobj = fileobj

        self.tarinfo = TarInfo()

    def list(self):
        """
        返回tar中的文件列表
        """


    def next(self):
        pass
    

    def __readblock(self, blocksize=1):
        block = b""
        data_len = 0

        while data_len < self.TARBLOCK:
            data = self.fileobj.read(self.TARBLOCK)
            if data == b"":
                return b""
            block += data 
            data_len += len(data_len)
        
        if data_len > self.TARBLOCK:
            self.data
        
        return block

    def __write(self, data):
        block = b""
