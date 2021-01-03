#!/usr/bin/env python3
# coding=utf-8
# date 2019-06-20 15:09:25
# author calllivecn <c-all@qq.com>

import io
import os
from os.path import join
import sys
import stat
import logging
from shutil import copyfileobj
from struct import pack, unpack, pack_into, unpack_from, Struct
from os import path

#--------------------------------------------------------
# Init
#--------------------------------------------------------
PWD = True
try:
    import pwd
except ModuleNotFoundError:
    PWD = False 

GRP = True
try:
    import grp
except ModuleNotFoundError:
    GRP = False


PROGRAM = path.basename(sys.argv[0])



logger = logging.getLogger()
stream = logging.StreamHandler(sys.stderr)
fmt = logging.Formatter("%(filename)s:%(lineno)d %(message)s", datefmt="%Y-%m-%d-%H:%M:%S")
stream.setFormatter(fmt)
logger.addHandler(stream)

logger.setLevel(logging.WARN)

version = "release v1.0"

__all__ = ["TarPaxInfo"]

NUL = b"\0"                     # the null character
BLOCKSIZE = 512                 # length of processing blocks
RECORDSIZE = BLOCKSIZE * 20     # length of records
#GNU_MAGIC = b"ustar  \0"        # magic gnu tar string
POSIX_MAGIC = b"ustar\x0000"    # magic posix tar string, 这是加上了 2B version 字段的.

LENGTH_NAME = 100               # maximum length of a filename
LENGTH_LINK = 100               # maximum length of a linkname
LENGTH_PREFIX = 155             # maximum length of the prefix field

REGTYPE = b"0"                  # regular file
AREGTYPE = b"\0"                # regular file
LNKTYPE = b"1"                  # link (inside tarfile)
SYMTYPE = b"2"                  # symbolic link
CHRTYPE = b"3"                  # character special device
BLKTYPE = b"4"                  # block special device
DIRTYPE = b"5"                  # directory
FIFOTYPE = b"6"                 # fifo special device
CONTTYPE = b"7"                 # contiguous file

XHDTYPE = b"x"                  # POSIX.1-2001 extended header
XGLTYPE = b"g"                  # POSIX.1-2001 global header

USTAR_FORMAT = 0                # POSIX.1-1988 (ustar) format
GNU_FORMAT = 1                  # GNU tar format
PAX_FORMAT = 2                  # POSIX.1-2001 (pax) format


#---------------------------------------------------------
# tarfile constants
#---------------------------------------------------------
# File types that tarfile supports:
SUPPORTED_TYPES = (REGTYPE, AREGTYPE, LNKTYPE,
                   SYMTYPE, DIRTYPE, FIFOTYPE,
                   CONTTYPE, CHRTYPE, BLKTYPE)

# File types that will be treated as a regular file.
REGULAR_TYPES = (REGTYPE, AREGTYPE,
                 CONTTYPE)


# Fields from a pax header that override a TarInfo attribute.
#PAX_FIELDS = ("path", "linkpath", "size", "mtime", "atime",
#              "uid", "gid", "uname", "gname")

# Fields from a pax header that are affected by hdrcharset.
# 保留字段： realtime.any security.any
PAX_NAME_FIELDS = ("path", "linkpath", "size", "mtime", "atime",
              "uid", "gid", "uname", "gname", "comment", "hdrcharset")

# Fields in a pax header that are numbers, all other fields
# are treated as strings.
PAX_NUMBER_FIELDS = {
    "atime": float,
    "ctime": float,
    "mtime": float,
    "uid": int,
    "gid": int,
    "size": int
}


#--------------------------------------------------------
# Exception 
#--------------------------------------------------------
class TarError(Exception):
    """Base exception"""
    pass

class ExtractError(TarError):
    """General exception for extract errors."""
    pass

class ReadError(TarError):
    """Exception for unreadable tar archives."""
    pass

class CompressionError(TarError):
    """Exception for unavailable compression methods."""
    pass

class HeaderError(TarError):
    """Base exception for header errors."""
    pass

class EmptyHeaderError(HeaderError):
    """Exception for empty headers."""
    pass

class InvalidHeaderError(HeaderError):
    """Exception for invalid headers."""
    pass

#---------------------------------------------------------
# Some useful functions
#---------------------------------------------------------

def stn(s, length):
    """Convert a string to a null-terminated bytes object.
    """
    s = s.encode("utf-8")
    return s[:length] + (length - len(s)) * NUL

def nts(s):
    """Convert a null-terminated bytes object to a string.
    """
    p = s.find(b"\0")
    if p != -1:
        s = s[:p]
    return s.decode("utf-8")

def nti(s):
    """Convert a number field to a python number.
    """
    # There are two possible encodings for a number field, see
    # itn() below.
    if s[0] in (0o200, 0o377):
        n = 0
        for i in range(len(s) - 1):
            n <<= 8
            n += s[i + 1]
        if s[0] == 0o377:
            n = -(256 ** (len(s) - 1) - n)
    else:
        try:
            s = nts(s)
            n = int(s.strip() or "0", 8)
        except ValueError:
            raise InvalidHeaderError("invalid header")
    return n

def itn(n, digits=8):
    """Convert a python number to a number field.
    """
    # POSIX 1003.1-1988 requires numbers to be encoded as a string of
    # octal digits followed by a null-byte, this allows values up to
    # (8**(digits-1))-1. GNU tar allows storing numbers greater than
    # that if necessary. A leading 0o200 or 0o377 byte indicate this
    # particular encoding, the following digits-1 bytes are a big-endian
    # base-256 representation. This allows values up to (256**(digits-1))-1.
    # A 0o200 byte indicates a positive number, a 0o377 byte a negative
    # number.
    n = int(n)
    if 0 <= n < 8 ** (digits - 1):
        #s = bytes("%0*o" % (digits - 1, n), "ascii") + NUL
        s = bytes("{:0>{}o}".format(n, digits - 1), "ascii")  + NUL
    else:
        raise ValueError("overflow in number field")

    return s

def calc_chksums(buf):
    """Calculate the checksum for a member's header by summing up all
       characters except for the chksum field which is treated as if
       it was filled with spaces. According to the GNU tar sources,
       some tars (Sun and NeXT) calculate chksum with signed char,
       which will be different if there are chars in the buffer with
       the high bit set. So we calculate two checksums, unsigned and
       signed.
    """
    unsigned_chksum = 256 + sum(unpack_from("148B8x356B", buf))
    signed_chksum = 256 + sum(unpack_from("148b8x356b", buf))
    return unsigned_chksum, signed_chksum

def fillto512(data):
    s, c = divmod(len(data), BLOCKSIZE)

    if c > 0:
       data += bytes(BLOCKSIZE - c)
       s += 1

    return s, c


class UnixFile:

    def __init__(self, realpath):
        self.realpath = realpath

        if self.startwith(path.sep):
            logger.warning(f"{PROGRAM}: 去掉 “{path.sep}”符号.")
            self.path = self.realpath.lstrip(path.sep)
        else:
            self.path = self.realpath
    



class UstarHeader:

    def __init__(self):
        pass

    def set_pax_ext_header(self):
        pass

    def set_pax_ext_data(self):
        """

        """
        pass


    def set_ustar_header(self, typeflag, mode, size):
        pass



class TarInfo:
    """
    tar file detail info

    创建tar文件： 
    tar = TarInfo(tarfileobj)
    tar.addfile("filename") 
        .
        .
        .
    tar.addfile("more")
    tar.close()


    解压tar文件：
    tar = TarInfo(tarfileobj)
    tar.extrace2file("arcname", "dest") | tar.extrace2stream("arcname", streamobj)
    
    tar.close()
    """

    #__slots__ = ("path", "name", "linkpath", "mode", "uid", "gid", "size", "atime", "mtime",
    #             "typeflag", "uname", "gname",
    #             "devmajor", "devminor")
    #__all__ = []

    def __init__(self, filename = ""):
        """
        ustar 文件头
        以下注释的 字段 都在 POSIX tar 里有对应的了。
        """

        #self.name = "" # 以 NUL 结尾
        self.ustar_mode = 0o644
        #self.uid = 0
        #self.gid = 0
        self.ustar_size = 0
        #self.mtime = 0.0
        self.chksum = b"        "
        self.ustar_typeflag = b"0"
        #self.linkname = "" # 以 NUL 结尾

        self.magic = POSIX_MAGIC # 6B 以 NUL 结尾,  self.version = "" # 2B

        #self.uname = None # 以 NUL 结尾
        #self.gname = None # 以 NUL 结尾
        self.devmajor = 0
        self.devminor = 0
        #self.prefix = "" # 以 NUL 结尾
        self.ustar_padding = 0
        """
        字段 magic, uname, gname 是以 NUL 结尾的字符串。 name, linkname, prefix, 也是。
        version 是包含字符的两个八位字节的"00"。
        每个数字字段都以一个或多个<space>或NUL字符结尾
        """

        # 拓展头 name 字段
        self.pax_ext_header_flag = b"@PaxHeader Author=ZhangXu Repositories=https://github.com/calllivecn/tar.py"

        self.pax_header = {}

        # 操作时需要搬到的
        self.realpath = filename

        if self.realpath:
            self.__get_file_metadata()


    #----------------------------------------------------
    # 私有函数 begin
    #----------------------------------------------------

    def make_header(self):

        ext_data = self.__make_pax_data()

        # 创建 pax 拓展头
        self.ustar_typeflag = XHDTYPE
        ext_header = self.__make_pax_header()

        # 创建 ustar 文件头
        self.ustar_typeflag = self.typeflag
        self.ustar_size = 0
        self.ustar_padding = self.paddig
        ustar_header = self.__make_ustar_header(self.typeflag, self.mode, 0)

        return ext_header + ext_data + ustar_header
        
    def __make_pax_data(self):
        """
        把 self.pax_header 拓展记录转成bytes
        """
        records = b""
        for keyword, value in self.pax_header.items():

            k = keyword.encode("utf-8")

            if keyword in PAX_NAME_FIELDS:
                if keyword in PAX_NUMBER_FIELDS:
                    if keyword == "size":
                        # 换成八进制
                        v = bytes("{:o}".format(value), "ascii")
                    else:
                        v = bytes(str(value), "ascii")
                else:
                    v = value.encode("utf-8")
            else:
                logger.warning(f"{k} 不在 PAX_NAME_FIELDS里.")
                k = bytes(keyword)
                v = bytes(value)

            l = len(k) + len(v) + 3   # " " + "=" + "\n"

            n = p = 0

            while True:
                n = l + len(str(p))
                if n == p:
                    break
                p = n
        
            records += bytes(str(p), "ascii") + b" " + k + b"=" + v + b"\n"
        
        self.ustar_size, self.ustar_padding = fillto512(records)

        return bytes(records) + bytes(self.padding)


    def __get_pax_header(self):
        pass

    def __make_pax_header(self):

        self.ustar = bytearray(BLOCKSIZE)

        # ustar field

        # name : len(name) = 100
        self.ustar[0:len(self.pax_ext_header_name)] = self.pax_ext_header_name

        # mode : 0000644\0 
        self.ustar[100:108] = bytes("{:0>7o}".format(self.pax_mode & 0o7777), "ascii") + NUL

        # size : 这里是指拓展头的大小
        self.ustar[124:136] = bytes("{:0>11o}".format(self.pax_size), "ascii") + NUL

        # chksum <用space,用计算> 不用在这里， chksum 时 加上256就行
        # ustar[148:156] = b"        "

        # typeflag
        self.ustar[156:157] = XHDTYPE
        #ustar[156:157] = b"g" 

        # magic(6) + version(2) = 8byte
        self.ustar[257:265] = POSIX_MAGIC

        # major
        self.ustar[329:337] = bytes("{:0>7o}".format(0), "ascii") + NUL

        # minor
        self.ustar[337:345] = bytes("{:0>7o}".format(0), "ascii") + NUL

        # padding 12B
        self.ustar[500:512] = bytes("{:0>11o}".format(self.ustar_padding), "ascii") + NUL

        # chksum
        chksum = calc_chksums(self.ustar)[0]
        self.ustar[148:156] = bytes("{:0>7o}".format(chksum), "ascii") + NUL


        if self.typeflag == CHRTYPE or self.typeflag == BLKTYPE:
            self.devmajor = self.major
            self.devminor = self.minor
        
        ext_data = self.__make_pax_data()

        self.ustar_typeflag = XHDTYPE
        #self.ustar_mode =  放到 self.__make_pax_data()
        #self.ustar_size = 
        self.ustar_padding = len(ext_data)

        return bytes(self.ustar) + ext_data

    def __make_ustar_header(self):
        """
        实际上就是ustar模式的一个ext头
        """

        self.ustar = bytearray(BLOCKSIZE)

        pax_ext_header_name = b"@PaxHeader Author=ZhangXu Repositories=https://github.com/calllivecn/tar.py"
        # ustar field

        # name : len(name) = 100
        self.ustar[0:len(pax_ext_header_name)] = pax_ext_header_name

        # mode : 0000644\0 
        self.ustar[100:108] = bytes("{:0>7o}".format(self.ustar_mode & 0o7777), "ascii") + NUL

        # size : 这里是指拓展头的大小
        self.ustar[124:136] = bytes("{:0>11o}".format(self.ustar_size), "ascii") + NUL

        # chksum <用space,用计算> 不用在这里， chksum 时 加上256就行
        # ustar[148:156] = b"        "

        # typeflag
        self.ustar[156:157] = self.ustar_typeflag
        #ustar[156:157] = b"g" 

        # magic(6) + version(2) = 8byte
        self.ustar[257:265] = POSIX_MAGIC

        # major
        self.ustar[329:337] = bytes("{:0>7o}".format(self.devmajor), "ascii") + NUL

        # minor
        self.ustar[337:345] = bytes("{:0>7o}".format(self.devminor), "ascii") + NUL

        # padding 12B
        self.ustar[500:512] = bytes("{:0>11o}".format(self.ustar_padding), "ascii") + NUL

        # chksum
        chksum = calc_chksums(self.ustar)[0]
        self.ustar[148:156] = bytes("{:0>7o}".format(chksum), "ascii") + NUL

        return bytes(self.ustar)
    

    def __get_ustar_header(self, fileobj):
        buf = fileobj.read(BLOCKSIZE)


    def __get_file_metadata(self):

        tmp = self.realpath.replace(os.sep, "/")

        self.path = tmp.lstrip("/")

        #self.name = self.path
        self.pax_header["path"]  = self.path

        if hasattr(os, "lstat"):
            fstat = os.lstat(self.realpath)
        else:
            fstat = os.stat(self.realpath)


        self.mode = fstat.st_mode

        st_mode = fstat.st_mode

        if stat.S_ISREG(st_mode):
            """
            先不支持硬链接文件，把硬链接当普通文件处理。
            """

            #inode = (fstat.st_ino, fstat.st_dev)

            #if fstat.st_nlink > 1 and inode in self.indoes and self.fullname != self.inodes[inode]:
            #    typeflag = LNKTYPE
            #else:
            #    typeflag = REGTYPE
            #    if inode[0]:
            #        self.inodes[inode] = self.fullname

            self.typeflag = REGTYPE

        elif stat.S_ISDIR(st_mode):
            self.typeflag = DIRTYPE

        elif stat.S_ISFIFO(st_mode):
            self.typeflag = FIFOTYPE

        elif stat.S_ISLNK(st_mode):
            self.typeflag = SYMTYPE
            self.linkpath = os.readlink(self.realpath)
            self.pax_header["linkpath"] = self.linkpath

        elif stat.S_ISCHR(st_mode):
            self.typeflag = CHRTYPE

        elif stat.S_ISBLK(st_mode):
            self.typeflag = BLKTYPE

        else:
            logger.warning("不支持的文件类型：{}".format(self.realpath))

        if self.typeflag in REGULAR_TYPES:
            #self.size = fstat.st_size
            self.pax_header["size"] = self.size
        else:
            self.pax_size = 0
            self.pax_header["size"] = self.size

            self.major = os.major(fstat.st_dev)
            self.minor = os.minor(fstat.st_dev)

        self.blackcount, c = divmod(self.size, BLOCKSIZE)
        if c > 0:
            self.blackcount += 1
            self.paddig = BLOCKSIZE - c
            self.fillsize = self.padding
        else:
            self.padding = 0

        self.uid = fstat.st_uid
        self.pax_header["uid"] = self.uid

        self.gid = fstat.st_gid
        self.pax_header["gid"] = self.gid

        if PWD:
            self.uname = pwd.getpwuid(fstat.st_uid).pw_name
            self.pax_header["uname"] = self.uname

        if GRP:
            self.gname = grp.getgrgid(fstat.st_gid).gr_name
            self.pax_header["gname"] = self.gname

        self.atime = fstat.st_atime
        self.mtime = fstat.st_mtime

        self.pax_header["atime"] = self.atime
        self.pax_header["mtime"] = self.mtime


    #----------------------------------------------------
    # 私有函数 end
    #----------------------------------------------------


def test():
    logger.setLevel(logging.DEBUG)
    
    out_tar = open(sys.argv[1], "wb")

    for f in sys.argv[2:]:
        tarinfo = TarInfo(f)
        header = tarinfo.make_header()
        
        out_tar.write(header)

        logger.debug("{} :typeflag: {}".format(tarinfo.realpath, tarinfo.typeflag))

        if tarinfo.typeflag in REGULAR_TYPES:
            with open(f, "rb") as fp:
                copyfileobj(fp, out_tar)

            if tarinfo.fillsize != 0:
                logger.debug("tarinfo.fillsize: {}".format(tarinfo.fillsize))
                out_tar.write(bytes(tarinfo.fillsize))


    out_tar.write(bytes(BLOCKSIZE * 2))

    out_tar.close()

def prints():
    print("posix magic: ", POSIX_MAGIC)

if __name__ == "__main__":
    prints()
    test()
