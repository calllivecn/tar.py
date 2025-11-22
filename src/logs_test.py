# ...existing code...
import sys
import logging
import os
import traceback
from pathlib import Path

# 临时监控：记录谁关闭或重定向了 stderr
_log_path = Path("/tmp/stderr-close-trace.log")

def _append_trace(note: str):
    try:
        with _log_path.open("a") as f:
            f.write(f"\n--- {note} ---\n")
            traceback.print_stack(file=f)
    except Exception:
        pass

# patch sys.stderr.close（如果存在）
orig_stderr = getattr(sys, "stderr", None)
if orig_stderr is not None:
    orig_stderr_close = getattr(orig_stderr, "close", None)
    def _stderr_close(*a, **kw):
        _append_trace("sys.stderr.close called")
        if orig_stderr_close:
            return orig_stderr_close(*a, **kw)
    try:
        orig_stderr.close = _stderr_close
    except Exception:
        # 某些环境下不能替换方法，忽略
        pass

# patch os.close，检测 fd==2
_orig_os_close = os.close
def _os_close(fd, *a, **kw):
    if fd == 2:
        _append_trace("os.close(2) called")
    return _orig_os_close(fd, *a, **kw)
os.close = _os_close

# patch os.dup2，检测把其它 fddup 到 2 的操作
_orig_dup2 = os.dup2
def _dup2(oldfd, newfd, *a, **kw):
    if newfd == 2 or oldfd == 2:
        _append_trace(f"os.dup2({oldfd}, {newfd}) called")
    return _orig_dup2(oldfd, newfd, *a, **kw)
os.dup2 = _dup2

# ...existing code...
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
# ...existing code...