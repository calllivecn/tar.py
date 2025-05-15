# -*- coding: utf-8 -*-

import sys
import logging


def getlogger(level=logging.WARNING):
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s", datefmt="%Y-%m-%d-%H:%M:%S")
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    logger = logging.getLogger("AES")
    logger.setLevel(level)
    logger.addHandler(stream)
    return logger


def getlogger_print():
    fmt2 = logging.Formatter("%(message)s")
    stream2 = logging.StreamHandler(sys.stderr)
    stream2.setFormatter(fmt2)
    logger_print = logging.getLogger("print")
    # logger_print.setLevel(logging.WARNING)
    logger_print.setLevel(logging.INFO)
    logger_print.addHandler(stream2)
    return logger_print
    

logger = getlogger()

logger_print = getlogger_print()

