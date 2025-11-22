# -*- coding: utf-8 -*-

import sys
import logging


def getlogger(level=logging.WARNING):
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s", datefmt="%Y-%m-%d-%H:%M:%S")
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    logger = logging.getLogger("AES")
    # 使用传入的 level，并防止重复添加 handler 和向上传播
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(stream)
    logger.propagate = False
    return logger


def getlogger_print():
    fmt2 = logging.Formatter("%(message)s")
    stream2 = logging.StreamHandler(sys.stderr)
    stream2.setFormatter(fmt2)
    logger_print = logging.getLogger("print")
    logger_print.setLevel(logging.INFO)
    if not logger_print.handlers:
        logger_print.addHandler(stream2)
    logger_print.propagate = False
    return logger_print
    

logger = getlogger()

logger_print = getlogger_print()

