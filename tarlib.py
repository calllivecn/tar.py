#!/usr/bin/env python3
# coding=utf-8
# date 2019-06-20 15:09:25
# author calllivecn <c-all@qq.com>

import io
import os
import sys
import stat
import logging
from struct import pack, unpack, pack_into, unpack_from, Struct
from shutil import copyfileobj

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
POSIX_MAGIC = b"ustar\x0000"    # magic posix tar string

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
REGULAR_TYPES = (REGTYPE, AREGTYPE, CONTTYPE)


# Fields from a pax header that override a TarInfo attribute.
PAX_FIELDS = ("path", "linkpath", "size", "mtime", "atime",
              "uid", "gid", "uname", "gname")

# Fields from a pax header that are affected by hdrcharset.
PAX_NAME_FIELDS = {"path", "linkpath", "uname", "gname"}

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

    return data

class Tar:
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
    tar.extrace("arcname", "dest_dir")
    
    tar.close()
    """

    #__slots__ = ("path", "name", "linkpath", "mode", "uid", "gid", "size", "atime", "mtime",
    #             "typeflag", "uname", "gname",
    #             "devmajor", "devminor")
    #__all__ = []

    def __init__(self, tarfileobj = None):

        self.tarfileobj = tarfileobj

        self.realpath = ""
        self.path = ""
        self.name = ""
        self.linkpath = ""
        self.mode = 0o644
        self.uid = 0
        self.gid = 0
        self.size = 0 
        self.atime = 0.0
        self.mtime = 0.0
        self.typeflag = b"0"
        self.uname = 0
        self.gname = 0
        self.devmajor = NUL * 8
        self.devminor = NUL * 8

        self.pax_header = {}

        # ustar 512 fill data size
        self.fillsize = 0


    def addfile(self, filename):

        self.realpath = filename

        self.__get_file_metadata()

        header = self.__make_header()
        self.tarfileobj.write(header)

        
        if self.typeflag in REGULAR_TYPES:
            with open(self.realpath, "rb") as fp:
                copyfileobj(fp, self.tarfileobj)

        if self.fillsize != 0:
            logger.debug("tarinfol.fillsize: {}".format(self.fillsize))
            self.tarfileobj.write(bytes(self.fillsize))


        if os.path.isdir(self.realpath):
            
            for r, f, d in os.walk(self.realpath):
                
                for fs in d + f:

                    self.realpath = os.path.join(r,fs)

                    self.__get_file_metadata()
                    header = self.__make_header()
                    self.tarfileobj.write(header)
        
                    if self.typeflag in REGULAR_TYPES:
                        with open(self.realpath, "rb") as fp:
                            copyfileobj(fp, self.tarfileobj)

                    if self.fillsize != 0:
                        logger.debug("tarinfol.fillsize: {}".format(self.fillsize))
                        self.tarfileobj.write(bytes(self.fillsize))



    def close(self):
        self.tarfileobj.write(bytes(BLOCKSIZE * 2))


    #----------------------------------------------------
    # 私有函数 begin
    #----------------------------------------------------

    def __make_header(self):
        ext_header = self.__make_pax_header()
        ustar_header = self.__make_ustar_header(self.typeflag, self.mode, 0)

        return ext_header + ustar_header
        
    def __make_pax_header(self):
        """
        把 self.pax_header 拓展记录转成bytes
        """
        records = b""
        for keyword, value in self.pax_header.items():

            k = keyword.encode("utf-8")

            if keyword in PAX_NAME_FIELDS:
                v = value.encode("utf-8")
            elif keyword in PAX_NUMBER_FIELDS:
                if keyword == "size":
                    v = bytes("{:o}".format(value), "ascii")
                else:
                    v = bytes(str(value), "ascii")

            l = len(k) + len(v) + 3   # " " + "=" + "\n"
            n = p = 0
            while True:
                n = l + len(str(p))
                if n == p:
                    break
                p = n
        
            records += bytes(str(p), "ascii") + b" " + k + b"=" + v + b"\n"

        return self.__make_ext_header(len(records)) + fillto512(records)


    def __get_pax_header(self):
        pass

    def __make_ext_header(self, pax_header_len):

        return self.__make_ustar_header(XHDTYPE, self.mode, pax_header_len)

    def __make_ustar_header(self, typeflag, mode, size):

        """
        实际上就是ustar模式的一个ext头
        """

        pax_ext_header = b"./PaxHeader author=ZhangXu repositories=https://github.com/calllivecn/tar.py"
        ustar = bytearray(BLOCKSIZE)

        # ustar field

        # name : len(name) = 100
        ustar[0:len(pax_ext_header)] = pax_ext_header

        # mode : 0000644\0 
        ustar[100:108] = bytes("{:0>7o}".format(mode & 0o7777), "ascii") + NUL

        # size : 这里是指拓展头的大小
        ustar[124:136] = bytes("{:0>11o}".format(size), "ascii") + NUL

        # chksum <用space,用计算>
        ustar[148:156] = b"        "

        # typeflag
        ustar[156:157] = typeflag
        #ustar[156:157] = b"g" 

        # magic(6) + version(2) = 8byte
        ustar[257:265] = POSIX_MAGIC

        # major
        ustar[329:337] = self.devmajor

        # minor
        ustar[337:345] = self.devmajor

        # chksum
        chksum = calc_chksums(ustar)[0]
        ustar[148:156] = bytes("{:0>7o}".format(chksum), "ascii") + NUL

        return bytes(ustar)

    def __get_ustar_header(self, fileobj):

        buf = fileobj.read(BLOCKSIZE)


    def __get_file_metadata(self):

        self.path = ""
        self.name = ""
        self.linkpath = ""
        self.mode = 0o644
        self.uid = 0
        self.gid = 0
        self.size = 0 
        self.atime = 0.0
        self.mtime = 0.0
        self.typeflag = b"0"
        self.uname = 0
        self.gname = 0
        self.devmajor = NUL * 8
        self.devminor = NUL * 8

        self.pax_header = {}

        # ustar 512 fill data size
        self.fillsize = 0


        tmp = self.realpath.replace(os.sep, "/")
        self.path = tmp.lstrip("/")
        self.name = self.path
        self.pax_header["path"]  = self.path

        if hasattr(os, "lstat"):
            fstat = os.lstat(self.realpath)
        else:
            fstat = os.stat(self.realpath)


        self.mode = fstat.st_mode

        if stat.S_ISREG(self.mode):
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

        elif stat.S_ISDIR(self.mode):
            self.typeflag = DIRTYPE
            if not self.realpath.endswith("/"):
                self.realpath += "/"

        elif stat.S_ISFIFO(self.mode):
            self.typeflag = FIFOTYPE

        elif stat.S_ISLNK(self.mode):
            self.typeflag = SYMTYPE
            self.linkpath = os.readlink(self.realpath)
            self.pax_header["linkpath"] = self.linkpath

        elif stat.S_ISCHR(self.mode):
            self.typeflag = CHRTYPE
            self.major = os.major(fstat.st_dev)
            self.minor = os.minor(fstat.st_dev)

        elif stat.S_ISBLK(self.mode):
            self.typeflag = BLKTYPE
            self.major = os.major(fstat.st_dev)
            self.minor = os.minor(fstat.st_dev)

        else:
            logger.warn("不支持的文件类型：{}".format(self.realpath))

        if self.typeflag in REGULAR_TYPES:
            self.size = fstat.st_size
            self.pax_header["size"] = self.size
        else:
            self.size = 0
            self.pax_header["size"] = self.size

        s, c = divmod(self.size, BLOCKSIZE)
        if c > 0:
            self.fillsize = BLOCKSIZE - c

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

    tarinfo = Tar(out_tar)

    for f in sys.argv[2:]:
        tarinfo.addfile(f)

    tarinfo.close()
    out_tar.close()


if __name__ == "__main__":
    test()
