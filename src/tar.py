#!/usr/bin/env python3
# coding=utf-8
# date 2019-03-20 16:43:36
# update 2022-08-18 09:39:39
# https://github.com/calllivecn


import os
import sys
import logging
import getpass
import tarfile

import util
from libargparse import parse_args
from logs import logger, logger_print


NEWTARS = (".tar.zst", ".tar.aes", ".tar.zst.aes", ".tz", ".ta", ".tza")
TARFILE = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz")


def create(args, shafuncs):
    manager = util.ThreadManager()

    p = manager.add_task(util.tar2pipe, args.target, None, args.verbose, args.excludes, name="tar --> pipe")

    if args.z:
        p = manager.add_task(util.compress, p, None, args.level, args.threads, name="zstd")

    if args.e:
        p = manager.add_task(util.encrypt, p, None, args.k, args.prompt, name="encrypt")

    if len(shafuncs) > 0:
        fork = util.Pipefork()
        p4 = fork.fork()
        sha = fork.fork()

        # 从里把管道流分成两条
        manager.add_task(util.to_pipe, p, fork, name="to pipe")
        manager.add_pipe(fork)
        p = p4
        manager.add_task(util.shasum, shafuncs, sha, args.sha_file, name="shasum")

    if args.split and (args.f or args.O):
        logger_print.info(f"--split 和 (-f 或者 -O) 不能同时使用.")
        sys.exit(1)

    if args.split:
        p = manager.add_task(util.split, p, None, args.split, args.f, name="split size")

    # 最后写入到文件, 还需要处理到标准输出
    if args.f:
        f = open(args.f, "wb")
    else:
        f = sys.stdout.buffer
    
    manager.add_task(util.to_file, p, f, name="to file")


    manager.join_threads()
    manager.close_pipes()

    if f is not sys.stdout.buffer:
        f.close()


def extract4file(args):
    # 解压*.tar.gz *.tar.xz *.tar.bz2
    if not args.e and not args.z:
        try:
            util.extract(args.f, args.C, args.verbose, args.safe_extract)
        except tarfile.ReadError:
            logger.warning(f"{args.f}: 不是一个tar文件")
            sys.exit(0)
    
    # 解压后缀：*.tar.zst, *.tar.zst.aes, *.tz, *.tza
    else:
        with open(args.f.resolve(), "rb") as f:

            manager = util.ThreadManager()

            p = manager.add_task(util.to_pipe, f, None, name="to pipe")

            if args.e:
                p = manager.add_task(util.decrypt, p, None, args.k, name="decrypt")
    
            if args.z:
                p = manager.add_task(util.decompress, p, None, name="decompress")
    
            try:
                util.pipe2tar(p, args.C, args.verbose, args.safe_extract)
            except tarfile.ReadError:
                logger_print.info(f"解压: {NEWTARS} 需要指定，-z|-e 参数。")
                sys.exit(1)

            manager.join_threads()
            manager.close_pipes()
            # 关闭管道


def extract4stdin(args):
    """
    从标准输入解压时，如果是*.tar.zst.aes类型文件，需要指定-z 和 -e。
    """
    f = sys.stdin.buffer

    # 解压*.tar.gz *.tar.xz *.tar.bz2
    if not args.e and not args.z:
        # 从标准输入提取
        try:
            util.extract(f, args.C, args.verbose, args.safe_extract)
        except tarfile.ReadError:
            logger.warning(f"{f}: 不是一个tar文件")
            sys.exit(0)

    else:

        manager = util.ThreadManager()

        p = manager.add_task(util.to_pipe, f, None, name="to pipe")

        if args.e:
            p = manager.add_task(util.decrypt, p, None, args.k, name="decrypt")
    
        if args.z:
            p = manager.add_task(util.decompress, p, None, name="decompress")
    
        try:
            util.pipe2tar(p, args.C, args.verbose, args.safe_extract)
        except tarfile.ReadError:
            logger_print.info(f"解压: {NEWTARS} 需要指定，-z|-e 参数。")
            sys.exit(1)

        manager.join_threads()
        manager.close_pipes()


def extract(args):
    """
    解压：
    1. 从文件读取和从标准输入读取。
    2. gz, z2, xz 文件和新的zst|zst+aes。
    3. 解压时输出只能是路径
    """

    if args.f is None or args.O:
        extract4stdin(args)
    else:
        extract4file(args)


def __tarlist(f, args):
    pytar = True
    # 从文件提取
    try:
        util.tarlist(f, args.verbose)
    except tarfile.ReadError:
        logger.warning(f"当前标准输入, 不是一个tar文件")
        pytar = False
    
    if pytar:
        sys.exit(0)


def tarlist4stdin(args):
    f = sys.stdin.buffer

    __tarlist(f, args)

    manager = util.ThreadManager()

    p = manager.add_task(util.to_pipe, f, None, name="stdin to pipe")

    if args.e:
        p = manager.add_task(util.decrypt, f, None, args.k)
    
    if args.z:
        p = manager.add_task(util.decompress, p, None, name="decompress")
    
    try:
        util.pipe2tarlist(p, args.verbose)
    except tarfile.ReadError:
        logger_print.info(f"从标准输入解压: {NEWTARS} 需要指定，-z|-e 参数。")
        sys.exit(1)

    manager.join_threads()
    manager.close_pipes()
    # 关闭管道
    f.close()


def tarlist4file(args, suffix: str):
    """
    处理tar文件
    tar.zst, tar.zst.aes, tar.tz, tar.tza
    """

    __tarlist(args.f, args)

    manager = util.ThreadManager()

    with open(args.f.resolve(), "rb") as f:

        p = manager.add_task(util.to_pipe, f, None, name="tarlist4file")

        # 解压后缀：*.tar.zst, *.tar.zst.aes, *.tz, *.tza;
        if suffix in (".tar.zst.aes", ".tza", ".ta"):
            # 需要解密
            p = manager.add_task(util.decrypt, p, None, args.k, name="decrypt")

        elif suffix in (".tar.zst", ".tz"):
            p = manager.add_task(util.decompress, p, None, name="decompress")

        else:
            raise tarfile.ReadError(f"未知格式文件")
    
        # 处理管道
        try:
            util.pipe2tarlist(p, args.verbose)
        except tarfile.ReadError:
            logger.warning(f"{args.f}: 不是一个tar文件")
            sys.exit(1)


def tarlist(args):

    # 如果args.f是None，需要从标准输入读取
    if args.f is None or args.O:
        tarlist4stdin(args)
    else:
        # 解压后缀：*.tar.zst, *.tar.zst.aes, *.tz, *.tza;
        suffixs = args.f.suffixes
        suffix = "".join(suffixs)
        if suffix in NEWTARS:
            tarlist4file(args, suffix)

        elif suffix in TARFILE:
            util.tarlist(args.f, args.verbose)

        else:
            raise tarfile.ReadError(f"未知格式文件")

    
def main():
    parse, args = parse_args()

    if args.help:
        parse.print_help()
        sys.exit(0)

    if args.parse:
        logger_print.info(args)
        sys.exit(0)
    

    if args.verbose == 1:
        logger_print.setLevel(logging.INFO)

    if args.debug == 1:
        logger.setLevel(logging.INFO)
    elif args.debug == 2:
        logger.setLevel(logging.DEBUG)

    # hash 算计
    shafuncs = {"sha256"}
    # shafuncs = args.shafuncs # 初步尝试不行
    if args.md5:
        shafuncs |= {"md5"}

    if args.sha1:
        shafuncs |= {"sha1"}

    if args.sha224:
        shafuncs |= {"sha224"}

    if args.sha256:
        shafuncs |= {"sha256"}

    if args.sha384:
        shafuncs |= {"sha384"}

    if args.sha512:
        shafuncs |= {"sha512"}
    
    if args.blake2b:
        shafuncs |= {"blake2b"}
    
    if args.sha_all:
        shafuncs |= set(("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b"))
    
    if args.e:
        if args.k:
            password = args.k
        else:
            password = getpass.getpass("Password:")
            if args.c:
                password2 = getpass.getpass("Password(again):")
                if password != password2:
                    logger_print.info("password mismatches.")
                    sys.exit(2)
        args.k = password

    # 创建archive
    if args.c:
        if args.C:
            os.chdir(args.C)

        if len(args.target) == 0:
            logger_print.info(f"{sys.argv[0]}: 谨慎地拒绝创建空归档文件", file=sys.stderr)
            sys.exit(1)

        create(args, shafuncs)

    elif args.x:
        extract(args)

    elif args.list:
        tarlist(args)
    
    elif args.info:
        try:
            util.prompt(args.info)
        except Exception:
            logger_print.info(f"不是加密文件或文件损坏")
            sys.exit(1)

    else:
        logger_print.info("-c|-x|-t|--info 参数之一是必须的")
        sys.exit(1)


if __name__ == "__main__":
    main()

