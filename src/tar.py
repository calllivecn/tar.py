#!/usr/bin/env python3
# coding=utf-8
# date 2019-03-20 16:43:36
# update 2022-08-18 09:39:39
# https://github.com/calllivecn


import os
import sys
import getpass
import tarfile
from threading import Thread


import util
from libargparse import (
    parse_args,
)

def create(args, shafuncs):
    # 收集关闭read的close2()。
    pipes = []

    # 在主线程执行完的时候，分支线程可能 没执行完。需要收集分支线程，在 close2() 之前 join()
    fork_threads = []

    p = util.Pipe()
    th1 = Thread(target=util.tar2pipe, args=(args.target, p, args.verbose, args.excludes), name="tar 2 pipe", daemon=True)
    th1.start()
    pipes.append(p)

    if args.z:
        p2 = util.Pipe()
        th2 = Thread(target=util.compress, args=(p, p2, args.level, args.threads), name="zstd", daemon=True)
        th2.start()
        p = p2
        pipes.append(p)

    if args.e:
        p3 = util.Pipe()

        if args.k:
            password = args.k
        else:
            password = getpass.getpass("Password:")
            password2 = getpass.getpass("Password(again):")
            if password != password2:
                print("password mismatches.")
                sys.exit(2)

        th3 = Thread(target=util.encrypt, args=(p, p3, password, args.prompt), name="encrypt", daemon=True)
        th3.start()
        p = p3
        pipes.append(p)

    """
    if args.split:
        p2 = util.Pipe()
        th2 = Thread(target=util.split, args=(p1, p2, args.level, args.T), daemon=True)
        th2.start()
        p2.close()
    """

    if len(shafuncs) > 0:
        fork = util.Pipefork()
        p4 = fork.fork()
        sha = fork.fork()

        # 从里把管道流分成两条
        th_fork = Thread(target=util.to_pipe, args=(p, fork), name="to pipe", daemon=True)
        th_fork.start()
        p = p4

        th4 = Thread(target=util.shasum, args=(shafuncs, sha, args.sha_file), name="shasum", daemon=True)
        th4.start()
        fork_threads.append(th4)
        pipes.append(fork)

    
    # 最后写写入到文件, 还需要处理输出到标准输出的
    if args.f:
        f = open(args.f, "wb")
    else:
        f = sys.stdout.buffer
    
    util.to_file(p, f)

    [ th.join() for th in fork_threads]
    [ p.close2() for p in pipes]


def extract(args):
    """
    解压分：
    1. 从文件读取和从标准输入读取。
    2. gz, z2, xz 文件和新的zst|zst+aes。
    """

    pytar = True
    # 从文件提取
    try:
        if args.f:
            util.extract(args.f.resolve(), args.C, args.verbose, args.safe_extract)
        else:
            util.extract(sys.stdin.buffer, args.C, args.verbose, args.safe_extract)
    except tarfile.ReadError:
        pytar = False
    
    
    if pytar:
        sys.exit(0)

    # 解压后缀：*.tar.zst, *.tar.zst.aes, *.tz, *.tza;
    suffixs = args.f.suffixes
    suffix = "".join(suffixs)
    NEWTARS = (".tar.zst", ".tar.aes", ".tar.zst.aes", ".tz", ".ta", ".tza")
    if suffix not in NEWTARS:
        raise tarfile.ReadError(f"未知格式文件")

    pipes = []
    fork_threads = []
    p = util.Pipe()
    if args.f:
        f = open(args.f.resolve(), "rb")
        th1 = Thread(target=util.to_pipe, args=(f, p), daemon=True)
    else:
        th1 = Thread(target=util.to_pipe, args=(sys.stdin.buffer, p), daemon=True)
    
    th1.start()
    pipes.append(p)
    fork_threads.append(th1)

    if args.e:
        if args.k:
            password = args.k
        else:
            password = getpass.getpass("Password:")

        p2 = util.Pipe()
        th2 = Thread(target=util.decrypt, args=(p, p2, password), daemon=True)
        th2.start()

        p = p2

        pipes.append(p)
        fork_threads.append(th2)
    
    if args.z:
        p3 = util.Pipe()
        th3 = Thread(target=util.decompress, args=(p, p3), daemon=True)
        th3.start()

        p = p3

        pipes.append(p)
        fork_threads.append(th3)
    
    # extract pipe 2 tar
    try:
        util.pipe2tar(p, args.C, args.verbose, args.safe_extract)
    except tarfile.ReadError:
        print(f"解压: {NEWTARS} 需要指定，-z|-e 参数。", file=sys.stderr)
        sys.exit(1)

    [th.join() for th in fork_threads]
    [p.close2() for p in pipes]


def tarlist(args):
    pytar = True
    # 从文件提取
    try:
        if args.f:
            util.tarlist(args.f.resolve(), args.C, args.verbose)
        else:
            util.tarlist(sys.stdin.buffer, args.C, args.verbose)
    except tarfile.ReadError:
        pytar = False
    
    
    if pytar:
        sys.exit(0)

    # 解压后缀：*.tar.zst, *.tar.zst.aes, *.tz, *.tza;
    suffixs = args.f.suffixes
    suffix = "".join(suffixs)
    NEWTARS = (".tar.zst", ".tar.aes", ".tar.zst.aes", ".tz", ".ta", ".tza")
    if suffix not in NEWTARS:
        raise tarfile.ReadError(f"未知格式文件")

    pipes = []
    fork_threads = []
    p = util.Pipe()
    if args.f:
        f = open(args.f.resolve(), "rb")
        th1 = Thread(target=util.to_pipe, args=(f, p), daemon=True)
    else:
        th1 = Thread(target=util.to_pipe, args=(sys.stdin.buffer, p), daemon=True)
    
    th1.start()
    pipes.append(p)
    fork_threads.append(th1)

    if args.e:
        if args.k:
            password = args.k
        else:
            password = getpass.getpass("Password:")

        p2 = util.Pipe()
        th2 = Thread(target=util.decrypt, args=(p, p2, password), daemon=True)
        th2.start()

        p = p2

        pipes.append(p)
        fork_threads.append(th2)
    
    if args.z:
        p3 = util.Pipe()
        th3 = Thread(target=util.decompress, args=(p, p3), daemon=True)
        th3.start()

        p = p3

        pipes.append(p)
        fork_threads.append(th3)
    
    # extract pipe 2 tar
    try:
        util.pipe2tarlist(p, args.C, args.verbose)
    except tarfile.ReadError:
        print(f"解压: {NEWTARS} 需要指定，-z|-e 参数。", file=sys.stderr)
        sys.exit(1)

    [th.join() for th in fork_threads]
    [p.close2() for p in pipes]


def main():
    parse, args = parse_args()

    if args.help:
        parse.print_help()
        sys.exit(0)

    if args.parse:
        print(args)
        sys.exit(0)

    # hash 算计
    shafuncs = set()
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
    
    if args.C:
        os.chdir(args.C)

    # 创建archive
    if args.c:
        if len(args.target) == 0:
            print(f"{sys.argv[0]}: 谨慎地拒绝创建空归档文件", file=sys.stderr)
            sys.exit(1)
        create(args, shafuncs)

    elif args.x:
        extract(args)

    elif args.list:
        tarlist(args)

    else:
        print("-c|-x|-t 参数之一是必须的")
        sys.exit(1)


if __name__ == "__main__":
    main()

