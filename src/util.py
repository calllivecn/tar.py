#!/usr/bin/env python3
# coding=utf-8
# date 2022-08-19 01:00:45
# author calllivecn <calllivecn@outlook.com>

from typing import (
    Optional,
)


import os
import io
import sys
import tarfile
import hashlib
import threading
from queue import Queue, Empty, Full
from pathlib import Path
from struct import Struct
from fnmatch import fnmatchcase
from contextlib import contextmanager
import traceback

from pyzstd import (
    CParameter,
    # DParameter,
    ZstdCompressor,
    ZstdDecompressor,
)


import libcrypto
from protocols import (
    cast,
    ReadWrite,
)

from logs import logger, logger_print


# zstd 的标准压缩块大小是256K , 按 pyzstd 文档里写的使用2MB块
# pipe buf size
BLOCKSIZE = 1 << 21 # 2M


def cpu_physical() -> int:
    """
    原来的方法，不好跨平台。
    """
    cpu = os.cpu_count()
    if cpu is None:
        cpu = 1
    use, _ = divmod(cpu, 2)
    if use <= 1:
        return 1
    elif use > 8:
        return 8
    else:
        return use


# tarfile.open() 需要 fileobj 需要包装一下。
# ~~官道实现 pipe(os.pipe): 是两个FD 需要 关闭两次, 写关闭时: read() -> b""~~
# 队列实现queue.Queue: 需要放入一个结束标志 b""
class Pipe:
    """
    ~~pipe: True 使用 so.pipe() 管道, 删除旧代码 os.pipe()的支持~~
    pipe: False 时，使用队列。queue.Queue 写关闭时： read() -> b""~~
    """

    def __init__(self, stop_event: threading.Event):
        self.stop_event = stop_event
        self.q = Queue(32)
        self._buf = b""

        self._eof = False
    
    def read(self, size: int) -> bytes:
        """
        目前只在加密使用到指定read(size)大小读取：。
        先简单点
        """
        if self._eof:
            return b""

        if size < 0:
            raise ValueError("不能小于0字节大小")

        data = b""

        if self._buf:
            data = self._buf
            self._buf = b""

        else:
            while not self.stop_event.is_set():
                try:
                    data = self.q.get(timeout=0.5)
                except Empty:
                    # logger.debug("Q.get(timeout0.5)")
                    continue

                break
        
        m = len(data)
        if m > size:
            self._buf = data[size:]
            data = data[:size]
        
        if data == b"":
            # logger.debug("Pipe.read() 读取到结束标志 b''")
            self._eof = True
        return data

    def write(self, data: bytes) -> int:
        # logger.debug(f"{self.q.qsize()=}  Pipe.write() 写入数据大小: {len(data)}")
        # 不写入空数据，占用q队列空间
        if not data:
            return 0

        l_data = len(data)
        while not self.stop_event.is_set():
            try:
                self.q.put(data, timeout=0.5)
                return l_data
            except Full:
                continue
        return 0


    def close(self):
        self.q.put(b"")


class Pipefork:
    r"""
                 / --> read(stream1, size)
    write() --> |
                 \ --> read(stream2, size)
                  \ --> read(stram3, size)
                   \ --> ...
                    \ --> ...
    
    """
    def __init__(self, stop_event: threading.Event):
        """
        fork >=2, 看着可以和pipe 功能合并。
        """
        self.pipes: list[Pipe] = []
        self.stop_event = stop_event
    
    def fork(self) -> Pipe:
        pipe = Pipe(self.stop_event)
        self.pipes.append(pipe)
        return pipe
    
    def write(self, data: bytes) -> int:
        n = 0
        for pipe in self.pipes:
            n = pipe.write(data)
        return n

    def close(self):
        pipe: Pipe
        for pipe in self.pipes:
            pipe.close()


@contextmanager
def open_stream(path: Path|str, mode: str):
    """
    通用打开流：path 为 "-" 时返回标准输入/输出的 buffer，否则打开文件。
    只在实际打开文件时负责关闭流；标准流不关闭。
    """
    if path == "-" or path is None:
        if "r" in mode:
            yield cast(ReadWrite, sys.stdin.buffer)
        elif "w" in mode:
            yield cast(ReadWrite, sys.stdout.buffer)
        else:
            raise ValueError("unsupported mode for std stream")
    else:
        f = open(path, mode+"b")
        try:
            yield cast(ReadWrite, f)
        finally:
            f.close()

##################
# compress 相关处理函数
##################

def compress(rpipe: ReadWrite, wpipe: ReadWrite, level: int, threads: int):

    op = {
        CParameter.compressionLevel: level,
        CParameter.nbWorkers: threads,
    }

    Zst = ZstdCompressor(level_or_option=op)
    logger.debug(f"压缩等级: {level}, 线程数: {threads}")

    while (tar_data := rpipe.read(BLOCKSIZE)) != b"":
        # 有时候写入的数据少(或者压缩的好)，会返回空
        zdata = Zst.compress(tar_data)
        if zdata:
            wpipe.write(zdata)

    wpipe.write(Zst.flush())

    logger.debug("压缩完成")
    wpipe.close()


def decompress(rpipe: ReadWrite, wpipe: ReadWrite):
    # 解压没有 nbWorkers 参数
    zst = ZstdDecompressor()
    while (zst_data := rpipe.read(BLOCKSIZE)) != b"":
        tar_data = zst.decompress(zst_data)
        if tar_data:
            wpipe.write(tar_data)
    wpipe.close()

##################
# crypto 相关处理函数
##################

def encrypt(rpipe: ReadWrite, wpipe: ReadWrite, password, prompt):
    aes = libcrypto.AESGCM(password, (1<<21))
    aes.encrypt(rpipe, wpipe, prompt)
    logger.debug("加密完成")
    wpipe.close()

def decrypt(rpipe: ReadWrite, wpipe: ReadWrite, password):
    data = rpipe.read(2)

    if len(data) == 1:
        data += rpipe.read(1)

    if len(data) < 2:
        raise ValueError("无法读取文件版本信息。或者文件版本信息错误。")

    file_version = Struct("!H").unpack(data)[0]
    logger.debug(f"文件版本: {hex(file_version)}")
    
    # 使用Argon2id 进行密码哈希 + AESGCM256 加密。
    if file_version == 0x0003:
        logger.debug("使用 AES-GCM 格式进行加密/解密。")
        aes = libcrypto.AESGCM(password, (1<<21))

    elif file_version in (0x0001, 0x0002):
        logger.debug("使用 AES-CFB 格式进行加密/解密。")
        aes = libcrypto.AESCrypto(password)

    else:
        raise ValueError("不支持的文件版本。或者文件版本信息错误。")

    aes.decrypt(rpipe, wpipe, file_version)
    wpipe.close()

# 查看加密提示信息
def prompt(path: Path):
    libcrypto.fileinfo(path)



##################
# tar 相关处理函数
##################


def order_bad_path(tarinfo: tarfile.TarInfo):
    """
    处理掉不安全 tar 成员路径(这样有可能会产生冲突而覆盖文件):
    ../../dir1/file1 --> dir1/file1
    注意：使用 Path() 包装过的路径，只会剩下左边的"../"; 所以可以这样处理。
    """
    path = Path(tarinfo.name)
    cwd = Path()
    for part in path.parts:
        if part == "..":
            continue
        else:
            cwd = cwd / part

    tarinfo.name = str(cwd)



def extract(readable: ReadWrite, path: Path, verbose=False, safe_extract=False):
    """
    这里只需要处理 tar 的解压流。
    """
    tar: tarfile.TarFile
    with tarfile.open(mode="r|*", fileobj=readable) as tar:
        while (tarinfo := tar.next()) is not None:
            if ".." in tarinfo.name:
                if safe_extract:
                    logger.info(f"成员路径包含 `..' 不提取: {tarinfo.name}")
                else:
                    logger.info(f"成员路径包含 `..' 提取为: {tarinfo.name}")
                    order_bad_path(tarinfo)

            if verbose:
                logger_print.info(f"{tarinfo.name}")

            # 安全的直接提取
            tar.extract(tarinfo, path, filter=tarfile.data_filter)


# def tarlist(readable: Path | BinaryIO | io.BufferedReader, verbose=False):
def tarlist(readable: Path | ReadWrite, verbose=False):
    """
    些函数只用来解压: tar, tar.gz, tar.bz2, tar.xz, 包。
    """
    tar: tarfile.TarFile
    if isinstance(readable, Path):
        with tarfile.open(readable, mode="r:*") as tar:
                tar.list(verbose)

    elif hasattr(readable, "read"):
        # 从标准输入提取
        with tarfile.open(mode="r|*", fileobj=readable) as tar:
            tar.list(verbose)

        # tarfile fileobj 需要自行关闭
        readable.close()
    
    else:
        raise ValueError("参数错误")


def filter(tarinfo: tarfile.TarInfo, verbose=False, fs=[]):
    for fm in fs:
        if fnmatchcase(tarinfo.name, fm):
            return None
    else:
        if verbose:
            logger_print.info(f"{tarinfo.name}")
        return tarinfo


# 创建
def tar2pipe(paths: list[Path], pipe: ReadWrite, verbose, excludes: list = []):
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
            tar.add(path, arcname, filter=lambda x: filter(x, verbose, excludes))
    
    logger.debug(f"打包完成: {paths}")
    pipe.close()


# 提取到路径下
def pipe2tar(pipe: ReadWrite, path: Path, verbose=False, safe_extract=False):
    tar: tarfile.TarFile
    with tarfile.open(mode="r|", fileobj=pipe) as tar:
        while (tarinfo := tar.next()) is not None:
            if ".." in tarinfo.name:
                if safe_extract:
                    logger_print.info(f"成员路径包含 `..' 不提取: {tarinfo.name}")
                else:
                    logger_print.info(f"成员路径包含 `..' 提取为: {tarinfo.name}")
                    order_bad_path(tarinfo)

            if verbose:
                logger_print.info(f"{tarinfo.name}")

            tar.extract(tarinfo, path, filter=tarfile.data_filter)


def pipe2tarlist(pipe: ReadWrite, verbose=False):
    tar: tarfile.TarFile
    with tarfile.open(mode="r|", fileobj=pipe) as tar:
        tar.list(verbose)


#################
# pipe 2 file and pipe 2 pipe
#################

def to_file(rpipe: ReadWrite, fileobj: ReadWrite):
    while (data := rpipe.read(BLOCKSIZE)) != b"":
        fileobj.write(data)
    logger.debug("to_file() 写入完成")
    fileobj.close()


def to_pipe(rpipe: ReadWrite, wpipe: ReadWrite):
    while (data := rpipe.read(BLOCKSIZE)) != b"":
        wpipe.write(data)
    logger.debug("to_pipe() 写入完成")
    wpipe.close()



#################
# hash 计算
#################
HASH = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b")
def shasum(shafuncnames: set, pipe: ReadWrite, outfile: Optional[Path]):
    logger.debug(f"计算hash: {shafuncnames}")
    shafuncs = []
    for funcname in sorted(shafuncnames):
        if funcname in HASH:
            shafuncs.append(hashlib.new(funcname))
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

    def split(self, prefix: str, splitsize: int, input: ReadWrite, output: Path):
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


def split_prefix(args) -> str:
    split_prefix = args.split_prefix

    if args.z:
        split_prefix = "data.tz"

    if args.e:
        split_prefix = "data.ta"

    if args.z and args.e:
        split_prefix = "data.tza"

    return split_prefix


def split(rpipe: ReadWrite, filename_prefix: str, splitsize: int, output_dir: Path):
    splitter = FileSplitterMerger()
    splitter.split(filename_prefix, splitsize, rpipe, output_dir)


def merge(prefix: str, input: Path, output: io.BufferedWriter):
    merger = FileSplitterMerger()
    merger.merge(prefix, input, output)


class ThreadManager:

    def __init__(self):
        self.threads: list[threading.Thread] = []
        self.pipes: list[Pipe] = []

        self.stop_event = threading.Event()

    def add_pipe(self, pipe=None):
        """
        添加一个管道。如果未提供管道，则创建一个新的管道。
        """
        if pipe is None:
            pipe = Pipe(self.stop_event)
        self.pipes.append(pipe)
        return pipe
    
    def task(self, func, *arguments, name=None, daemon=True):
        """
        直接添加一个任务，使用线程。
        - func: 任务函数
        - args: 额外的参数
        """
        thread = threading.Thread(target=self.func_wrapper, args=(func, *arguments), name=name)
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

        thread = threading.Thread(target=self.func_wrapper, args=(func, input_pipe, output_pipe, *arguments), name=name)
        thread.daemon = daemon
        thread.start()
        self.threads.append(thread)

        return output_pipe


    def func_wrapper(self, func, *arguments):
        # logger_print.info(f"线程 {threading.current_thread().name} 启动，执行函数: {func.__name__} 参数: {arguments}")
        try:
            func(*arguments)
        except Exception as e:
            traceback.print_exc()
            logger.error(f"线程 {threading.current_thread().name} 出现异常: {e}")
            self.stop_event.set()

    def join_threads(self):
        """
        等待所有线程完成。
        """
        for thread in self.threads:
            thread.join()
    
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