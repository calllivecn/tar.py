#!/usr/bin/env python3
# coding=utf-8
# date 2021-06-28 17:19:23
# https://github.com/calllivecn


import re
import sys
import glob
import argparse
from pathlib import Path

import util

class Argument(argparse.ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._positionals = self.add_argument_group("位置参数")
        self._optionals = self.add_argument_group("通用选项")


def compress_level(level):
    errmsg="压缩等级为：1 ~ 22"
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
        raise argparse.ArgumentTypeError(f"不支的切割单位, 必须是: {unit_chars}")

def target_exists(filename):
    p = Path(filename)
    if p.exists():
        return p
    else:
        raise argparse.ArgumentTypeError(f"{p} 不存在")


def exclude(glob_list):
    # glob
    for g in glob_list:
        glob.glob0(g)


def exclude_regex(regex_list):
    pass


Description='''\
POXIS tar 工具

例子:
    {0} -cf archive.tar foo bar         # 把 foo 和 bar 文件打包为 archive.tar 文件。
    {0} -zcf archive.tar.zst foo bar    # 把 foo 和 bar 文件打包为 archive.tar.zst 文件。
    {0} -tvf archive.tar                # 列出 archive.tar 里面的文件，-v 选项，列出详细信息。
    {0} -xf archive.tar                 # 解压 archive.tar 全部文件到当前目录。
'''.format(sys.argv[0])


def parse_args():

    parse = Argument(
        usage="%(prog)s [option] [file ... or directory ...]",
        description=Description,
        epilog="Author: calllivecn <c-all@qq.com>, Repositories: https://github.com/calllivecn/tar.py",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    
    # 位置参数
    parse.add_argument('target', nargs='*', type=target_exists, help='文件s | 目录s')

    parse.add_argument("-h", "--help", action="store_true", help="输出帮助信息")

    parse.add_argument("-f", type=Path, help="archive 文件, 没有这参数时，默认使用标准输入输出。")
    parse.add_argument("-C", type=target_exists, help="更改目录(default: .)")

    # 从标准输入读取
    # parse.add_argument("--stdin", action="store_true", help="从标准输入读取")
    # parse.add_argument("--stdout", action="store_true", help="输出到标准输出")
    parse.add_argument("-O", action="store_true", help="解压文件至标准输出")

    group1 = parse.add_mutually_exclusive_group()
    group1.add_argument("-c", action="store_true", help="创建tar文件")
    group1.add_argument("-x", action="store_true", help="解压tar文件")
    group1.add_argument("-t", "--list", action="store_true", help="输出tar文件内容")

    parse.add_argument("--safe-extract", dest="safe_extract", action="store_true", help="处理tar里不安全的路径后在解压")
    parse.add_argument("-v", "--verbose", action="count", help="输出详情")

    parse.add_argument("--exclude", dest="exclude", metavar="PATTERN", nargs="+", type=exclude, help="排除这类文件,使用 glob: PATTERN")
    parse.add_argument("--exclude-regex", dest="exclude_regex", metavar="PATTERN", nargs="+", type=exclude_regex, help="排除这类文件, 使用正则 PATTERN")

    # 这个工具只支持解压这些，创建时只使用zstd
    # group2 = parse.add_mutually_exclusive_group()
    # group2.add_argument('-z', '--gzip', action='store_true', help='filter the archive through gzip')
    # group2.add_argument('-j', '--bzip2', action='store_true', help='filter the archive through bzip2')
    # group2.add_argument('-J', '--xz', dest='xz', action='store_true', help='filter the archive through xz')

    parse_compress = parse.add_argument_group("压缩选项", description="只使用zstd压缩方案, 但可以解压 gz, bz2, xz。")
    parse_compress.add_argument("-z", action="store_true", help="使用zstd压缩(default: level=3)")
    parse_compress.add_argument("-l", dest="level", metavar="level", type=compress_level, default=3, help="指定压缩level: 1 ~ 22")
    parse_compress.add_argument("-T", dest="threads", metavar="threads", type=int, default=util.cpu_physical(), help="默认使用全部CPU物理核心")


    parse_encrypt = parse.add_argument_group("加密", description="使用aes-256-cfb加密算法")
    parse_encrypt.add_argument("-e", action="store_true", help="加密")
    parse_encrypt.add_argument("-k", type=str, metavar="PASSWORK", action="store", help="指定密码 (default：启动后交互式输入)")
    # parse_encrypt.add_argument("-d", action="store_true", help="解密")
    parse_encrypt.add_argument("--prompt", help="密码提示信息")

    parse_hash = parse.add_argument_group("计算输出文件的sha值")
    # parse_hash.add_argument(dest="shafuncs", default=set(), help=argparse.SUPPRESS)
    parse_hash.add_argument("--sha-file", dest="sha_file", metavar="FILENAME", action="store", help="哈希值输出到文件(default: stderr)")
    parse_hash.add_argument("--md5", action="store_true", help="下载同时计算 md5")
    parse_hash.add_argument("--sha1", action="store_true", help="下载同时计算 sha1")
    parse_hash.add_argument("--sha224", action="store_true", help="下载同时计算 sha224")
    parse_hash.add_argument("--sha256", action="store_true", help="下载同时计算 default: sha256")
    parse_hash.add_argument("--sha384", action="store_true", help="下载同时计算 sha384")
    parse_hash.add_argument("--sha512", action="store_true", help="下载同时计算 sha512")
    parse_hash.add_argument("--blake2b", action="store_true", help="下载同时计算 blake2b")
    parse_hash.add_argument("--sha-all", action="store_true", help="计算下列所有哈希值")

    parse_split = parse.add_argument_group("切割输出文件")
    parse_split.add_argument("--split", type=split_size, help="单个文件最大大小(单位：B, K, M, G, T, P。 例如: --split 256M)")
    # parse_split.add_argument("--split-filename", help="指定切割文件后缀")
    parse_split.add_argument("--suffix", help="指定切割文件后缀(default: 0000 ~ 9999)")

    parse.add_argument("--parse", action="store_true", help=argparse.SUPPRESS)

    return parse, parse.parse_args()

