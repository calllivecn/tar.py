#!/usr/bin/env python3
# coding=utf-8
# date 2022-08-19 01:00:45
# author calllivecn <calllivecn@outlook.com>

from typing import (
    Optional,
    BinaryIO,
)


import os
import io
import tarfile
import hashlib
import threading
from queue import Queue
from pathlib import Path
from fnmatch import fnmatchcase


IMPORT_ZSTD = True
try:
    # import zstd 这个库太简单了，不方便。改为使用 pyzstd
    from pyzstd import (
        CParameter,
        # DParameter,
        ZstdCompressor,
        ZstdDecompressor,
    )
except ModuleNotFoundError:
    IMPORT_ZSTD = False


import libcrypto


from logs import logger, logger_print


# zstd 的标准压缩块大小是256K , 按 pyzstd 文档里写的使用2MB块
# pipe buf size
BLOCKSIZE = 1 << 21 # 2M


def cpu_physical() -> int:
    """
    原来的方法，不好跨平台。
    """
    use, _ = divmod(os.cpu_count(), 2)
    if use <= 1:
        return 1
    else:
        return use

    """
    import platform

    OS = platform.system().lower()
    if OS == "windows":
        return os.cpu_count()

    elif OS == "linux":
        # 不太行。。 改为默认使用一半核心
        with open("/proc/cpuinfo") as f:
            while (line := f.readline()) != "":
                if "cpu cores" in line:
                    count = line.strip("\n")
                    break
                else:
                    # 没有 cpu cores 字段
                    return

        _, cores = count.split(":")
        return int(cores.strip())

    else:
        return os.cpu_count()
    """


# tarfile.open() 需要 fileobj 需要包装一下。
# pipe 是两个FD 需要 关闭两次, 写关闭时: read() -> b""
class Pipe:
    """
    pipe: True 使用 so.pipe() 管道
    pipe: False 时，使用队列。queue.Queue
    """

    def __init__(self, pipe: bool = True):
        if pipe:
            self.r, self.w = os.pipe()
        else:
            self.q = Queue(32)
    
    def read(self, size: int) -> bytes:
        return os.read(self.r, size)

    def write(self, data: bytes) -> int:
        return os.write(self.w, data)
    
    def close(self):
        os.close(self.w)
    
    def close2(self):
        os.close(self.r)


class Pipefork:
    r"""
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
        self.pipes: list[BinaryIO] = []
    
    def fork(self) -> Pipe:
        pipe: Pipe = Pipe()
        self.pipes.append(pipe)
        return pipe
    
    def write(self, data: bytes) -> int:
        for pipe in self.pipes:
            n = pipe.write(data)
        return n

    def close(self):
        pipe: Pipe
        for pipe in self.pipes:
            pipe.close()

    def close2(self):
        pipe: Pipe
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
    logger.debug(f"压缩等级: {level}, 线程数: {threads}")
    while (tar_data := rpipe.read(BLOCKSIZE)) != b"":
        wpipe.write(Zst.compress(tar_data))
        logger.debug(f"压缩数据大小: {len(tar_data)}")
    wpipe.write(Zst.flush())

    logger.debug("压缩完成")
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
    aes = libcrypto.AESCrypto(password)
    aes.encrypt(rpipe, wpipe, prompt)
    wpipe.close()

def decrypt(rpipe: Pipe, wpipe:Pipe, password):
    aes = libcrypto.AESCrypto(password)
    aes.decrypt(rpipe, wpipe)
    wpipe.close()

# 查看加密提示信息
def prompt(path: Path):
    libcrypto.fileinfo(path)

##################
# tar 相关处理函数
##################


def extract(readable: Path | BinaryIO | io.BufferedReader, path: Path, verbose=False, safe_extract=False):
    """
    些函数只用来解压: tar, tar.gz, tar.bz2, tar.xz, 包。
    """
    if isinstance(readable, Path):
        with tarfile.open(readable, mode="r:*") as tar:
            while (tarinfo := tar.next()) is not None:
                if ".." in tarinfo.name:
                    if safe_extract:
                        logger_print.info(f"成员路径包含 `..' 不提取: {tarinfo.name}")
                    else:
                        logger_print.info(f"成员路径包含 `..' 提取为: {tarinfo.name}")
                        order_bad_path(Path(tarinfo.name))

                if verbose:
                    logger_print.info(f"{tarinfo.name}")

                # 安全的直接提取
                tar.extract(tarinfo, path)

    elif isinstance(readable, BinaryIO) or isinstance(readable, io.BufferedReader):
        # 从标准输入提取
        with tarfile.open(mode="r|*", fileobj=readable) as tar:
            while (tarinfo := tar.next()) is not None:
                if ".." in tarinfo.name:
                    if safe_extract:
                        logger_print.info(f"成员路径包含 `..' 不提取: {tarinfo.name}")
                    else:
                        logger_print.info(f"成员路径包含 `..' 提取为: {tarinfo.name}")
                        order_bad_path(Path(tarinfo.name))

                if verbose:
                    logger_print.info(f"{tarinfo.name}")

                # 安全的直接提取
                tar.extract(tarinfo, path)

        # tarfile fileobj 需要自行关闭
        readable.close()
    
    else:
        raise ValueError("参数错误")


def tarlist(readable: Path | BinaryIO | io.BufferedReader, verbose=False):
    """
    些函数只用来解压: tar, tar.gz, tar.bz2, tar.xz, 包。
    """
    if isinstance(readable, Path):
        with tarfile.open(readable, mode="r:*") as tar:
                tar.list(verbose)

    elif isinstance(readable, BinaryIO) or isinstance(readable, io.BufferedReader):
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


def filter(tarinfo: tarfile.TarInfo, verbose=False, fs=[]):
    for fm in fs:
        if fnmatchcase(tarinfo.name, fm):
            return None
    else:
        if verbose:
            logger_print.info(f"{tarinfo.name}")
        return tarinfo


# 创建
def tar2pipe(paths: list[Path], pipe: Pipe, verbose, excludes: list = []):
    """
    处理打包路径安全:
    只使用 给出路径最右侧做为要打包的内容
    例："../../dir1/dir2" --> 只会打包 dir2 目录|文件
    """
    tar: tarfile.TarFile
    with tarfile.open(mode="w|", fileobj=pipe) as tar:
        for path in paths:
            abspath = path.resolve()
            arcname = abspath.relative_to(abspath.parent)

            # tar.add(path, arcname)
            tar.add(path, arcname, filter=lambda x: filter(x, verbose, excludes))
    
    logger.debug(f"打包完成: {paths}")
    pipe.close()


# 提取 zst
def pipe2tar(pipe: Pipe, path: Path, verbose=False, safe_extract=False):
    tar: tarfile.TarFile
    with tarfile.open(mode="r|", fileobj=pipe) as tar:
        while (tarinfo := tar.next()) is not None:
            if ".." in tarinfo.name:
                if safe_extract:
                    logger_print.info(f"成员路径包含 `..' 不提取: {tarinfo.name}")
                else:
                    logger_print.info(f"成员路径包含 `..' 提取为: {tarinfo.name}")
                    order_bad_path(Path(tarinfo.name))

            if verbose:
                logger_print.info(f"{tarinfo.name}")

            # 安全的直接提取
            tar.extract(tarinfo, path)


def pipe2tarlist(pipe: Pipe, verbose=False):
    with tarfile.open(mode="r|", fileobj=pipe) as tar:
        tar.list(verbose)


#################
# pipe 2 file and pipe 2 pipe
#################

def to_file(rpipe: Pipe, fileobj: BinaryIO):
    while (data := rpipe.read(BLOCKSIZE)) != b"":
        fileobj.write(data)
    logger.debug("to_file() 写入完成")


def to_pipe(rpipe: Pipe, wpipe: Pipe):
    while (data := rpipe.read(BLOCKSIZE)) != b"":
        wpipe.write(data)
    wpipe.close()
    logger.debug("to_pipe() 写入完成")



#################
# hash 计算
#################
HASH = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b")
def shasum(shafuncnames: set, pipe: Pipe, outfile: Optional[Path]):
    logger.debug(f"计算hash: {shafuncnames}")
    shafuncs = []
    for funcname in sorted(shafuncnames):
        if funcname in HASH:
            shafuncs.append(getattr(hashlib, funcname)())
        else:
            raise ValueError(f"只支持 {HASH} 算法")

    sha: hashlib._Hash
    while (data := pipe.read(BLOCKSIZE)) != b"":
        for sha in shafuncs:
            sha.update(data)
    
    for sha in shafuncs:
        logger_print.info(f"{sha.hexdigest()} {sha.name}")

    if isinstance(outfile, Path):
        with open(outfile, "w") as f:
            for sha in shafuncs:
                f.write(f"{sha.hexdigest()}\t{sha.name}\n")


#################
# split 切割
#################

class SplitError(Exception):
    pass


class FileSplitterMerger:

    def split(self, prefix: str, splitsize: int, input: Pipe, output: Path):
        """按指定的字节数将输入文件拆分为多个文件。"""
        file_count = 0
        bytes_written_current_file = 0
        outfile = None

        blocksize = min(BLOCKSIZE, splitsize)  # 动态调整 blocksize，确保不超过 bytes_per_file

        try:
            while True:
                # 读取数据块
                chunk = input.read(blocksize)
                if not chunk:
                    break  # 读取到文件末尾

                while chunk:  # 确保 chunk 被完全处理
                    # 如果当前文件未打开或已达到指定大小，则创建新文件
                    if outfile is None or bytes_written_current_file >= splitsize:
                        if outfile:
                            outfile.close()

                        out_filename = output / f"{prefix}.{file_count}"  # 使用零填充的编号
                        logger.debug(f"正在创建文件 '{out_filename}'")

                        outfile = open(out_filename, 'wb')
                        file_count += 1
                        bytes_written_current_file = 0

                    # 写入数据到当前文件
                    write_size = min(len(chunk), splitsize - bytes_written_current_file)
                    outfile.write(chunk[:write_size])
                    bytes_written_current_file += write_size

                    # 如果当前块未完全写入，则将剩余部分保留到下一轮
                    chunk = chunk[write_size:]

        finally:
            if outfile:
                outfile.close()

        return 0

    def merge(self, prefix: str, input: Path, output: io.BufferedWriter):
        """将具有指定前缀的多个文件合并为一个文件。"""

        try:
            file_generator = self.__file_generator(prefix)

            while True:
                filename = next(file_generator)

                file = Path(input) / filename

                if not file.exists():
                    logger.debug(f"{file}: 文件不存在，合并到此为止。")
                    break

                logger.info(f"正在合并文件 '{file}'")

                with open(file, 'rb') as infile:
                    while chunk := infile.read(BLOCKSIZE):
                        output.write(chunk)

        except Exception as e:
            logger_print.info(f"debug: {e}")

        finally:
            output.close()

    def __file_generator(self, prefix):
        """生成器：按后缀递增顺序生成文件名"""
        index = 0
        while True:
            file_name = Path(f"{prefix}.{index}")
            logger.debug(f"检查文件 '{file_name}'")

            yield file_name
            index += 1


# def split(rpipe: Pipe, splitsize: int,  input: Path, output_dir: Path, filename_prefix: str):
def split(rpipe: Pipe, filename_prefix: str, splitsize: int, output_dir: Path):
    splitter = FileSplitterMerger()
    splitter.split(filename_prefix, splitsize, rpipe, output_dir)


def merge(prefix: str, input: Path, output: io.BufferedWriter):
    merger = FileSplitterMerger()
    merger.merge(prefix, input, output)


class ThreadManager:
    def __init__(self):
        self.threads = []
        self.pipes = []

    def add_pipe(self, pipe=None):
        """
        添加一个管道。如果未提供管道，则创建一个新的管道。
        """
        if pipe is None:
            pipe = Pipe()
        self.pipes.append(pipe)
        return pipe
    
    def task(self,func, *arguments, name=None, daemon=True):
        """
        直接添加一个任务，使用线程池。
        - func: 任务函数
        - args: 额外的参数
        """
        thread = threading.Thread(target=func, args=arguments, name=name)
        thread.daemon = daemon
        thread.start()
        self.threads.append(thread)


    def add_task(self, func, input_pipe=None, output_pipe=None, *arguments, name=None, daemon=True):
        """
        添加一个任务，自动管理线程和管道。
        - func: 任务函数
        - input_pipe: 输入管道
        - output_pipe: 输出管道
        - args: 额外的参数
        """
        if output_pipe is None:
            output_pipe = self.add_pipe()

        thread = threading.Thread(target=func, args=(input_pipe, output_pipe, *arguments), name=name)
        thread.daemon = daemon
        thread.start()
        self.threads.append(thread)

        return output_pipe

    def join_threads(self):
        """
        等待所有线程完成。
        """
        thread: threading.Thread
        for thread in self.threads:
            thread.join()

    def close_pipes(self):
        """
        关闭所有管道。
        """
        pipe: Pipe
        for pipe in self.pipes:
            pipe.close2()

    def run_pipeline(self, tasks):
        """
        运行一组任务，自动连接管道。
        - tasks: [(func, args), ...]
        """
        input_pipe = None
        for func, args in tasks:
            output_pipe = self.add_pipe()
            self.add_task(func, input_pipe, output_pipe, *args)
            input_pipe = output_pipe
        return input_pipe