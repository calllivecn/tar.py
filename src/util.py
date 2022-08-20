#!/usr/bin/env python3
# coding=utf-8
# date 2022-08-19 01:00:45
# author calllivecn <c-all@qq.com>

from typing import (
    IO,
    BinaryIO,
    Set,
    Union,
    Callable,
)


import os
import sys
import tarfile
import hashlib
import threading
from pathlib import Path


IMPORT_ZSTD = True
try:
    # import zstd 这个库太简单了，不方便。改为使用 pyzstd
    from pyzstd import (
        CParameter,
        DParameter,
        ZstdCompressor,
        ZstdDecompressor,
    )
except ModuleNotFoundError:
    IMPORT_ZSTD = False


import libcrypto

# zstd 的标准压缩块大小是256K , 按 pyzstd 文档里写的使用2MB块
# pipe buf size
BLOCKSIZE = 1 << 21 # 2M


def cpu_physical() -> int:
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
    
    def read(self, size: int) -> bytes:
        return os.read(self.r, size)

    def write(self, data: bytes) -> int:
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
    
    def fork(self) -> Pipe:
        pipe = Pipe()
        self.pipes.append(pipe)
        return pipe
    
    def write(self, data: bytes) -> int:
        for pipe in self.pipes:
            n = pipe.write(data)
        return n

    def close(self):
        for pipe in self.pipes:
            pipe.close()

    def close2(self):
        for pipe in self.pipes:
            pipe.close2()


##################
# compress 相关处理函数
##################

def compress(rpipe: Pipe, wpipe: Pipe, level: int, threads: int):

    op = {
        CParameter.compressionLevel: level,
        CParameter.nbWorkers: threads,
        }

    Zst = ZstdCompressor(level_or_option=op)
    while (tar_data := rpipe.read(BLOCKSIZE)) != b"":
        wpipe.write(Zst.compress(tar_data))
    wpipe.write(Zst.flush())

    wpipe.close()


def decompress(rpipe: Pipe, wpipe: Pipe):
    # 解压没有 nbWorkers 参数
    zst = ZstdDecompressor()
    while (zst_data := rpipe.read(BLOCKSIZE)) != b"":
        tar_data = zst.decompress(zst_data)
        wpipe.write(tar_data)

    wpipe.close()


##################
# crypto 相关处理函数
##################

def encrypt(rpipe: Pipe, wpipe:Pipe, password, prompt):
    libcrypto.encrypt(rpipe, wpipe, password, prompt)
    wpipe.close()

def decrypt(rpipe: Pipe, wpipe:Pipe, password):
    libcrypto.decrypt(rpipe, wpipe, password)
    wpipe.close()

##################
# tar 相关处理函数
##################


def extract(readable: Union[Path, BinaryIO], path: Path, verbose=False, safe_extract=False):
    """
    些函数只用来解压: tar, tar.gz, tar.bz2, tar.xz, 包。
    """
    if isinstance(readable, Path):
        with tarfile.open(readable, mode="r:*") as tar:
            while (tarinfo := tar.next()) is not None:
                if ".." in tarinfo.name:
                    if safe_extract:
                        print("成员路径包含 `..' 不提取:", tarinfo.name, file=sys.stderr)
                    else:
                        print("成员路径包含 `..' 提取为:", tarinfo.name, file=sys.stderr)
                        order_bad_path(Path(tarinfo.name))

                if verbose:
                    print(tarinfo.name, file=sys.stderr)

                # 安全的直接提取
                tar.extract(tarinfo, path)

    elif isinstance(readable, BinaryIO):
        # 从标准输入提取
        with tarfile.open(mode="r|*", fileobj=readable) as tar:
            while (tarinfo := tar.next()) is not None:
                if ".." in tarinfo.name:
                    if safe_extract:
                        print("成员路径包含 `..' 不提取:", tarinfo.name, file=sys.stderr)
                    else:
                        print("成员路径包含 `..' 提取为:", tarinfo.name, file=sys.stderr)
                        order_bad_path(Path(tarinfo.name))

                if verbose:
                    print(tarinfo.name, file=sys.stderr)

                # 安全的直接提取
                tar.extract(tarinfo, path)

        # tarfile fileobj 需要自行关闭
        readable.close()
    
    else:
        raise ValueError("参数错误")


def tarlist(readable: Union[Path, BinaryIO], path: Path, verbose=False):
    """
    些函数只用来解压: tar, tar.gz, tar.bz2, tar.xz, 包。
    """
    if isinstance(readable, Path):
        with tarfile.open(readable, mode="r:*") as tar:
                tar.list(verbose)

    elif isinstance(readable, BinaryIO):
        # 从标准输入提取
        with tarfile.open(mode="r|*", fileobj=readable) as tar:
            while (tarinfo := tar.next()) is not None:
                tar.list(verbose)

        # tarfile fileobj 需要自行关闭
        readable.close()
    
    else:
        raise ValueError("参数错误")


def order_bad_path(tarinfo: tarfile.TarInfo):
    """
    处理掉不安全 tar 成员路径(这样有可能会产生冲突而覆盖文件):
    ../../dir1/file1 --> dir1/file1
    注意：使用 Path() 包装过的路径，只会剩下左边的"../"; 所有可以这样处理。
    """
    path = Path(tarinfo.name)
    cwd = Path()
    for part in path.parts:
        if part == "..":
            continue
        else:
            cwd = cwd / part

    tarinfo.name = str(cwd)


# 创建
def tar2pipe(paths: list[Path], pipe: Pipe, filter: Union[Callable, None] = None):
    """
    处理打包路径安全:
    只使用 给出路径最右侧做为要打包的内容
    例："../../dir1/dir2" --> 只会打包 dir2 目录|文件
    """
    with tarfile.open(mode="w|", fileobj=pipe) as tar:
        for path in paths:
            abspath = path.resolve()
            arcname = abspath.relative_to(abspath.parent)

            tar.add(path, arcname, filter=filter)

    pipe.close()


# 提取 zst
def pipe2tar(pipe: Pipe, path: Path, verbose=False, safe_extract=False):

    with tarfile.open(mode="r|", fileobj=pipe) as tar:
        while (tarinfo := tar.next()) is not None:
            if ".." in tarinfo.name:
                if safe_extract:
                    print("成员路径包含 `..' 不提取:", tarinfo.name, file=sys.stderr)
                else:
                    print("成员路径包含 `..' 提取为:", tarinfo.name, file=sys.stderr)
                    order_bad_path(Path(tarinfo.name))

            if verbose:
                print(tarinfo.name, file=sys.stderr)

            # 安全的直接提取
            tar.extract(tarinfo, path)


def pipe2tarlist(pipe: Pipe, path: Path, verbose=False):
    with tarfile.open(mode="r|", fileobj=pipe) as tar:
        tar.list(verbose)


#################
# pipe 2 file and pipe 2 pipe
#################

def to_file(rpipe: Pipe, fileobj: IO):
    # with open(filename, "wb") as f:
    while (data := rpipe.read(BLOCKSIZE)) != b"":
        fileobj.write(data)
    fileobj.close()

# fork 节点执行完后，需要关闭向后管的管道
def to_pipe(rpipe: Pipe, wpipe: Pipe):
    while (data := rpipe.read(BLOCKSIZE)) != b"":
        wpipe.write(data)
    wpipe.close()

#################
# split 计算
#################

def split(rpipe: Pipe, splitsize: int, filename: Path):
    while (data := rpipe.read(BLOCKSIZE)) != b"":
        pass


#################
# hash 计算
#################
HASH = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b")
def shasum(shafuncnames: Set, pipe: Pipe, outfile=Union[Path, None]):
    print("执行了吗？", shafuncnames)
    shafuncs = []
    for funcname in sorted(shafuncnames):
        if funcname in HASH:
            shafuncs.append(getattr(hashlib, funcname)())
        else:
            raise ValueError(f"只支持 {HASH} 算法")

    while (data := pipe.read(BLOCKSIZE)) != b"":
        for sha in shafuncs:
            sha.update(data)
    
    print("怎么没输出？")
    for sha in shafuncs:
        print(f"{sha.hexdigest()} {sha.name}", file=sys.stderr)

    if outfile is Path:
        with open(outfile, "w") as f:
            for sha in shafuncs:
                f.write(f"{sha.hexdigest()} \t {sha.name}")



# 怎么把每个处理器连接起来工作呢？

class executer:

    def __init__(self):
        
        self.end = False

        self.works = []

    def add_handle_pipe(self, funcs: Callable, *args, **kwargs):
        pipe = Pipe()
        th = threading.Thread(target=funcs, args=args, kwargs=kwargs, daemon=True)
        self.works.append(th)
    

    def start(self):
        pass
