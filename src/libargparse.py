#!/usr/bin/env python3
# coding=utf-8
# date 2021-06-28 17:19:23
# https://github.com/calllivecn


import re
import glob
import argparse

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
        raise argparse.ArgumentTypeError(f"不支的切割单位, 必须是: {unit_chars}")

def exclude(glob_list):
    # glob
    pass

def exclude_regex(regex_list):
    pass
