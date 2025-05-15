#!/usr/bin/env python3
# coding=utf-8
# date 2021-06-28 17:19:23
# https://github.com/calllivecn


import argparse
from argparse import (
    Namespace,
)
from pathlib import Path

import util
import version


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


def split_is_dir(path: str):
    p = Path(path)
    if not p.is_dir():
        raise argparse.ArgumentTypeError(f"{p} 不是一个目录")
    return p


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


Description='''\
POXIS tar 工具 + zstd + sha计算 + split大文件分割

例子:
    %(prog)s -cf archive.tar foo bar         # 把 foo 和 bar 文件打包为 archive.tar 文件。
    %(prog)s -zcf archive.tar.zst foo bar    # 把 foo 和 bar 文件打包为 archive.tar.zst 文件。
    %(prog)s -tvf archive.tar                # 列出 archive.tar 里面的文件，-v 选项，列出详细信息。
    %(prog)s -xf archive.tar                 # 解压 archive.tar 全部文件到当前目录。
    %(prog)s -ecf archive.tar                # 打包 archive.tar 后同时加密。
    %(prog)s -ezcf archive.tar.zst           # 打包 archive.tar.zst 后同时加密。
    %(prog)s --info archive.ta               # 查看提示信息,如果有的话。

    使用-t查看文件内容时， 如果文件后缀是(".tar.zst", ".tar.aes", ".tar.zst.aes", ".tz", ".ta", ".tza")需要指定对应的-z 或者 -e 参数。
    解压 *.tar.gz *.tar.xz *.tar.bz2 时，不要指定 -z 和 -e。

'''

def parse_args() -> tuple[Argument, Namespace]:

    parse = Argument(
        usage="%(prog)s [option] [file ... or directory ...]",
        description=Description,
        epilog=f"Author: calllivecn <calllivecn@outlook.com>, Version: {version.VERSION} Repositories: https://github.com/calllivecn/tar.py",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    
    parse.add_argument("-h", "--help", action="store_true", help="输出帮助信息")

    # 位置参数
    parse.add_argument('target', nargs='*', type=target_exists, help='文件s | 目录s')

    parse.add_argument("-f", type=Path, help="archive 文件, 没有这参数时，默认使用标准输入输出。")
    parse.add_argument("-C", type=target_exists, default=".", help="解压输出目录(default: .)")

    # 从标准输入读取 或者输出到标准输出
    parse.add_argument("-O", action="store_true", default=False, help="解压文件至标准输出")

    group1 = parse.add_mutually_exclusive_group()
    group1.add_argument("-c", action="store_true", help="创建tar文件")
    group1.add_argument("-x", action="store_true", help="解压tar文件")
    group1.add_argument("-t", "--list", action="store_true", help="输出tar文件内容")

    parse.add_argument("--safe-extract", dest="safe_extract", action="store_true", help="解压时处理tar里不安全的路径")
    parse.add_argument("-v", "--verbose", action="count", default=0, help="输出详情")
    parse.add_argument("-d", "--debug", action="count", default=0, help="输出debug详情信息")

    parse.add_argument("--excludes", dest="excludes", metavar="PATTERN", nargs="+", default=[], help="排除这类文件,使用Unix shell: PATTERN")
    # parse.add_argument("--excludes-regex", dest="excludes_regex", metavar="PATTERN", nargs="+", type=exclude_regex, help="排除这类文件, 使用正则 PATTERN")

    # 这个工具只支持解压这些，创建时只使用zstd
    # group2 = parse.add_mutually_exclusive_group()
    # group2.add_argument('-z', '--gzip', action='store_true', help='filter the archive through gzip')
    # group2.add_argument('-j', '--bzip2', action='store_true', help='filter the archive through bzip2')
    # group2.add_argument('-J', '--xz', dest='xz', action='store_true', help='filter the archive through xz')

    parse_compress = parse.add_argument_group("压缩选项", description="只使用zstd压缩方案, 但可以解压 *.tar.gz, *.tar.bz2, *.tar.xz。")
    parse_compress.add_argument("-z", action="store_true", help="使用zstd压缩(default: level=3)")
    parse_compress.add_argument("-l", dest="level", metavar="level", type=compress_level, default=3, help="指定压缩level: 1 ~ 22")
    parse_compress.add_argument("-T", dest="threads", metavar="threads", type=int, default=util.cpu_physical(), help="默认使用全部CPU物理核心")


    parse_encrypt = parse.add_argument_group("加密", description="使用aes-256-cfb加密算法")
    parse_encrypt.add_argument("-e", action="store_true", help="加密")
    parse_encrypt.add_argument("-k", type=str, metavar="PASSWORK", action="store", help="指定密码 (default：启动后交互式输入)")
    # parse_encrypt.add_argument("-d", action="store_true", help="解密")
    parse_encrypt.add_argument("--prompt", help="密码提示信息")
    parse_encrypt.add_argument("--info", type=target_exists, help="查看加密提示信息")

    parse_hash = parse.add_argument_group("计算输出文件的sha值")
    parse_hash.add_argument("--sha-file", dest="sha_file", metavar="FILENAME", action="store", type=Path, help="哈希值输出到文件(default: stderr)")
    parse_hash.add_argument("--md5", action="store_true", help="输出文件同时计算 md5")
    parse_hash.add_argument("--sha1", action="store_true", help="输出文件同时计算 sha1")
    parse_hash.add_argument("--sha224", action="store_true", help="输出文件同时计算 sha224")
    parse_hash.add_argument("--sha256", action="store_true", help="输出文件同时计算 default: sha256")
    parse_hash.add_argument("--sha384", action="store_true", help="输出文件同时计算 sha384")
    parse_hash.add_argument("--sha512", action="store_true", help="输出文件同时计算 sha512")
    parse_hash.add_argument("--blake2b", action="store_true", help="输出文件同时计算 blake2b")
    parse_hash.add_argument("--sha-all", action="store_true", help="计算以上所有哈希值")

    split_description = """
    在创建时分害会创建这里提供的目录。把文件名从-z -e这里生成。
    会根据 -z 和 -e 选项来生成对应后缀*.tar|*.t, *.tz, *.tza
    """
    parse_split = parse.add_argument_group("切割输出文件", description=split_description)
    parse_split.add_argument("--split", type=split_is_dir, help="切割时的输出目录 或者是 合并时的输入目录 (default: .)")
    parse_split.add_argument("--split-size", type=split_size, default="1G", help="单个文件最大大小(单位：B, K, M, G, T, P。 默认值：1G)")
    parse_split.add_argument("--split-prefix", default="data.tar", help="指定切割文件的前缀(default: data.tar) 其他几种: *.tar|*.t, *.tz, *.tza")
    # parse_split.add_argument("--suffix", default="00", help="指定切割文件后缀(default: 00 开始)" )
    parse_split.add_argument("--split-sha", action="store_true", help="计算切割文件的sha值。(default: sha256)")


    parse.add_argument("--parse", action="store_true", help=argparse.SUPPRESS)

    return parse, parse.parse_args()

