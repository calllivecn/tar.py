#!/usr/bin/env python3
#coding=utf-8
# date 2019-03-22 19:40:08
# author calllivecn <c-all@qq.com>

import os
import sys
import tarfile
import argparse


# tar begin


# tar end



Description='''类似 GNU tar 的工具。

例子:
  tar -cf archive.tar foo bar  # 把 foo 和 bar 文件打包为 archive.tar 文件。
  tar -tvf archive.tar         # 列出 archive.tar 里面的文件，-v 选项，列出详细信息。
  tar -xf archive.tar          # 解压 archive.tar 全部文件到当前目录。
'''

parse=argparse.ArgumentParser(
#description='%(prog)s [option...] [FILE]...',
usage=Description,
epilog="author: calllivecn <c-all@com> ，https://github.com/calllivecn/tar.py"
)


group1 = parse.add_mutually_exclusive_group()

group1.add_argument('-c', '--create', action='store_true', help='create a new archive')

group1.add_argument('-x', '--extract', action='store_true', help='extract files from an archive')

group1.add_argument('-t', '--list', action='store_true', help='list the contents of an archive')

parse.add_argument('-f', '--file', action='store', help='use archive file or device ARCHIVE')

parse.add_argument('-v', '--verbose', action='count', help='verbosely list files processed')

parse.add_argument('files', nargs='*', help='arvchive file or directory')

parse.add_argument('-C', '--directory', action='store', default = os.getcwd(), help='change to directory DIR')

group2 = parse.add_mutually_exclusive_group()

group2.add_argument('-z', '--gzip', action='store_true', help='filter the archive through gzip')

group2.add_argument('-j', '--bzip2', action='store_true', help='filter the archive through bzip2')

group2.add_argument('-J', '--xz', dest='xz', action='store_true', help='filter the archive through xz')

#parse.add_argument('--exclude',nargs='*',help='exclude files, given as a PATTERN')

args = parse.parse_args()



