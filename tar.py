#!/usr/bin/env python3
# coding=utf-8
# date 2019-03-20 16:43:36
# update 2021-06-27 18:30:23
# https://github.com/calllivecn


import os
import io
import re
import sys
import glob
import shutil
import tarfile
import argparse
from functools import partial

IMPORT_ZSTD = True
try:
    # import zstd 这个库太简单了，不方便使用
    import pyzstd
except NotImplementedError:
    IMPORT_ZSTD = False

# zstd 的标准压缩块大小是256K , 这里我使用1MB 块
# zstd.compress()
BLOCKSIZE = 1 << 20

class Tar:

    def __init__(self, instream, outstream):
        pass



class Argument(argparse.ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._positionals = self.add_argument_group("位置参数")
        self._optionals = self.add_argument_group("通用选项")


def compress_level(level):
    errmsg="压缩等级必须为：1 ~ 22"
    try:
        l = int(level)
    except Exception:
        raise argparse.ArgumentTypeError(errmsg)
    
    if l < 1 or l > 22:
        raise argparse.ArgumentTypeError(errmsg)

    return l

def split_size(unit_size):
    unit_chars = ("B", "K", "M", "G", "T", "P")
    try:
        u = unit_size[-1]
        if u in ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"):
            size = int(unit_size)
            u = "M"
        else:
            size = int(unit_size[:-1])

    except Exception:
        if u not in unit_chars:
            raise argparse.ArgumentTypeError(f"单位不正确: {unit_chars}")
    
    if u == "B":
        return size
    elif u == "K":
        return size*(1<<10)
    elif u == "M":
        return size*(1<<20)
    elif u == "G":
        return size*(1<<30)
    elif u == "T":
        return size*(1<<40)
    elif u == "P":
        return size*(1<<50)
    else:
        raise argparse.ArgumentTypeError("不支的切割单位")

def exclude(glob_list):
    # glob
    pass

def exclude_regex(regex_list):
    pass


Description='''\
POXIS tar 工具

例子:
    {0} -cf archive.tar foo bar  # 把 foo 和 bar 文件打包为 archive.tar 文件。
    {0} -tvf archive.tar         # 列出 archive.tar 里面的文件，-v 选项，列出详细信息。
    {0} -xf archive.tar          # 解压 archive.tar 全部文件到当前目录。
'''.format(sys.argv[0])


def main():
    import argparse

    parse = Argument(
        usage="%(prog)s [option] [file ... or directory ...]",
        description=Description,
        epilog="Author: calllivecn <c-all@com>, Repositories: https://github.com/calllivecn/tar.py",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    
    # 位置参数
    parse.add_argument('target', nargs='*', help='文件s | 目录s')

    parse.add_argument("-h", "--help", action="store_true", help="输出帮助信息")

    parse.add_argument("-f", help="tar 文件")
    parse.add_argument("-C", help="解压到指定目录(default: 当前目录)")
    # 从标准输入读取
    parse.add_argument("--stdin", action="store_true", help="从标准输入读取")
    parse.add_argument("--stdout", action="store_true", help="输出到标准输出")

    group1 = parse.add_mutually_exclusive_group()
    group1.add_argument("-c", action="store_true", help="创建tar文件")
    group1.add_argument("-x", action="store_true", help="解压tar文件")
    # group1.add_argument('-x', '--extract', action='store_true', help='extract files from an archive')
    group1.add_argument("-t", "--list", action="store_true", help="输出tar文件内容")

    parse.add_argument("-v", "--verbose", action="count", help="输出详情")

    parse.add_argument("--exclude", nargs="+", type=exclude, help="排除这类文件,使用 glob: PATTERN")
    parse.add_argument("--exclude-regex", nargs="+", type=exclude_regex, help="排除这类文件, 使用正则 PATTERN")

    # group2 = parse.add_mutually_exclusive_group()
    # group2.add_argument('-z', '--gzip', action='store_true', help='filter the archive through gzip')
    # group2.add_argument('-j', '--bzip2', action='store_true', help='filter the archive through bzip2')
    # group2.add_argument('-J', '--xz', dest='xz', action='store_true', help='filter the archive through xz')

    #parse.add_argument('--exclude',nargs='*',help='exclude files, given as a PATTERN')

    parse_compress = parse.add_argument_group("压缩选项", description="目前只使用zstd压缩方案")
    parse_compress.add_argument("-z", action="store_true", help="使用zstd压缩(default: level=10)")
    parse_compress.add_argument("-l", metavar="level", type=compress_level, default=10, help="指定压缩level: 1 ~ 22")

    parse_encrypto = parse.add_argument_group("加密", description="目前只使用aes-256-cfb")
    parse_encrypto.add_argument("-e", action="store_true", help="加密")
    parse_encrypto.add_argument("-k", metavar="PASSWORK", action="store", help="密码(default：交互式输入)")
    # parse_encrypto.add_argument("-d", action="store_true", help="解密")
    parse_encrypto.add_argument("--prompt", help="密码提示信息")

    parse_hash = parse.add_argument_group("输出同时计算sha值")
    parse_hash.add_argument("--sha-file",metavar="FILENAME", action="store", help="哈希值输出到文件(default: 输出到标准输出 or stderr)")
    parse_hash.add_argument("--md5", action="store_true", help="下载同时计算 md5")
    parse_hash.add_argument("--sha1", action="store_true", help="下载同时计算 sha1")
    parse_hash.add_argument("--sha224", action="store_true", help="下载同时计算 sha224")
    parse_hash.add_argument("--sha256", action="store_true", help="下载同时计算 sha256")
    parse_hash.add_argument("--sha384", action="store_true", help="下载同时计算 sha384")
    parse_hash.add_argument("--sha512", action="store_true", help="下载同时计算 sha512")
    parse_hash.add_argument("--sha-all", action="store_true", help="计算下列所有哈希值")

    parse_split = parse.add_argument_group("切割输出文件")
    parse_split.add_argument("--split", type=split_size, default="256M", help="单个文件最大大小(单位：B, K, M, G, T, P. default: 256M)")
    # parse_split.add_argument("--split-filename", help="指定切割文件后缀")
    parse_split.add_argument("--suffix", help="指定切割文件后缀(default: 0000 ~ 9999)")

    parse.add_argument("--parse", action="store_true", help=argparse.SUPPRESS)

    args = parse.parse_args()

    if args.help:
        parse.print_help()
        sys.exit(0)

    if args.parse:
        print(args)
        sys.exit(0)


if __name__ == "__main__":
    # read_tar()
    main()

