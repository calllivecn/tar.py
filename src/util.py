#!/usr/bin/env python3
# coding=utf-8
# date 2022-08-19 01:00:45
# author calllivecn <c-all@qq.com>


import os
import threading


from libcrypto import (
    encrypt,
    decrypt,
)

# zstd 的标准压缩块大小是256K , 按 pyzstd 文档里写的使用2MB块
# pipe buf size
BLOCKSIZE = 1 << 21 # 2M


def cpu_physical():
    with open("/proc/cpuinfo") as f:
        while (line := f.readline()) != "":
            if "cpu cores" in line:
                count = line.strip("\n")
                break

    _, cores = count.split(":")
    return int(cores.strip())


# tarfile.open() 需要 fileobj 需要包装一下。
# pipe 是两个FD 需要 关闭两次, 写关闭时: read() -> b""
class Pipe:

    def __init__(self):
        self.r, self.w = os.pipe()
    
    def read(self, size):
        return os.read(self.r, size)

    def write(self, data):
        return os.write(self.w, data)
    
    def close(self):
        os.close(self.w)
    
    def close2(self):
        os.close(self.r)


class Pipefork:
    """
                 / --> read(stream1, size)
    write() --> |
                 \ --> read(stream2, size)
                  \ --> read(stram3, size)
                   \ --> ...
                    \ --> ...
    
    """
    def __init__(self):
        """
        fork >=2, 看着可以和pipe 功能合并。
        """
        self.pipes = []
    
    def fork(self):
        pipe = Pipe()
        self.pipes.append(pipe)
        return pipe
    
    def write(self, data):
        for pipe in self.pipes:
            n = pipe.write(data)
        return n

    def close(self):
        for pipe in self.pipes:
            pipe.close()



IMPORT_ZSTD = True
try:
    # import zstd 这个库太简单了，不方便。改为使用 pyzstd
    import pyzstd
except ModuleNotFoundError:
    IMPORT_ZSTD = False


def compress(rpipe, wpipe, level, threads):

    op = {
        pyzstd.CParameter.compressionLevel: level,
        pyzstd.CParameter.nbWorkers: threads,
        }

    Zst = pyzstd.ZstdCompressor(option=op)
    while (tar_data := rpipe.read()) != b"":
        wpipe.write(Zst.compress(tar_data))
    wpipe.write(Zst.flush())


def decompress(rpipe, wpipe):
    # 解压没有 nbWorkers 参数
    zst = pyzstd.ZstdDecompressor()
    while (zst_data := rpipe.read(BLOCKSIZE)) != b"":
        tar_data = zst.decompress(zst_data)
        wpipe.write(tar_data)
    wpipe.write(zst.flush())


# 加密



def shasum(methods, pipe):
    while (data := pipe.read(BLOCKSIZE)) != b"":
        for method in methods:
            method.update(data)
    
    return list(map(lambda sha: sha.digit(), methods))

def checksha(method, shavalue, pipe):
    pass

