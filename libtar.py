#!/usr/bin/env python3
# coding=utf-8
# date 2021-06-28 17:16:29
# https://github.com/calllivecn

import queue
import tarfile
import threading

class Pipe:

    def __init__(self, queuesize):
        self.buf = queue.Queue(queuesize)
        self.pos = 0

    def write(self, data):
        self.len = len(data)
        self.pos += self.len
        self.buf.put(data)
        return self.len

    def read(self):
        return self.buf.get()
    
    def tell(self):
        return self.pos
    
    def close(self):
        print("有调用 close()")
        self.buf.put(b"")


class Tar:

    def __init__(self, mode, queuesize=1):

        self.pipe = Pipe(queuesize)

        if mode == "r":
            self.tarobj = tarfile.open(mode="r|", fileobj=self.pipe)
        elif mode == "w":
            self.tarobj = tarfile.open(mode="w|", fileobj=self.pipe)

    def add(self, *args, **kwargs):
        self.th = threading.Thread(target=self.tarobj.add, args=args, kwargs=kwargs)
        self.th.start()
        # self.tarobj.add(*args, **kwargs)

    def extractall(self, *args, **kwargs):
        self.th = threading.Thread(target=self.tarobj.extractall, args=args, kwargs=kwargs)
        self.th.start()
        # self.tarobj.extractall(*args, **kwargs)

    def list(self, *args, **kwargs):
        self.th = threading.Thread(target=self.tarobj.list, args=args, kwargs=kwargs)
        self.th.start()

    def join(self):
        self.th.join()
        self.tarobj.close()
        self.pipe.close()


def filter(tarinfo):
    tarinfo.name

    # --exclude
    if False:
        return None

    # 可以加入
    return tarinfo


