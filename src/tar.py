#!/usr/bin/env python3
# coding=utf-8
# date 2019-03-20 16:43:36
# update 2022-08-18 09:39:39
# https://github.com/calllivecn


import os
import sys

import util

from libargparse import (
    parse_args,
)


def main():
    parse, args = parse_args()

    if args.help:
        parse.print_help()
        sys.exit(0)

    if args.parse:
        print(args)
        sys.exit(0)


if __name__ == "__main__":
    main()

