# 类似 tar 工具

## 一般用法

```shell
tar.pyz -cf archive.tar foo bar         # 把 foo 和 bar 文件打包为 archive.tar 文件。
tar.pyz -zcf archive.tar.zst foo bar    # 把 foo 和 bar 文件打包为 archive.tar.zst 文件。
tar.pyz -tvf archive.tar                # 列出 archive.tar 里面的文件，-v 选项，列出详细信息。
tar.pyz -xf archive.tar                 # 解压 archive.tar 全部文件到当前目录。
```

## 详细用法

```shell
usage: tar.py [option] [file ... or directory ...]

POXIS tar 工具

例子:
    tar.py -cf archive.tar foo bar         # 把 foo 和 bar 文件打包为 archive.tar 文件。
    tar.py -zcf archive.tar.zst foo bar    # 把 foo 和 bar 文件打包为 archive.tar.zst 文件。
    tar.py -tvf archive.tar                # 列出 archive.tar 里面的文件，-v 选项，列出详细信息。
    tar.py -xf archive.tar                 # 解压 archive.tar 全部文件到当前目录。
    tar.py -ecf archive.tar                # 打包 archive.tar 后同时加密。
    tar.py -ezcf archive.tar.zst           # 打包 archive.tar.zst 后同时加密。
    tar.py --info archive.ta               # 查看提示信息,如果有的话。

位置参数:
  target                文件s | 目录s

通用选项:
  -h, --help            输出帮助信息
  -f F                  archive 文件, 没有这参数时，默认使用标准输入输出。
  -C C                  更改目录(default: .)
  -O                    解压文件至标准输出
  -c                    创建tar文件
  -x                    解压tar文件
  -t, --list            输出tar文件内容
  --safe-extract        解压时处理tar里不安全的路径
  -v, --verbose         输出详情
  --excludes PATTERN [PATTERN ...]
                        排除这类文件,使用Unix shell: PATTERN

压缩选项:
  只使用zstd压缩方案, 但可以解压 gz, bz2, xz。

  -z                    使用zstd压缩(default: level=3)
  -l level              指定压缩level: 1 ~ 22
  -T threads            默认使用全部CPU物理核心

加密:
  使用aes-256-cfb加密算法

  -e                    加密
  -k PASSWORK           指定密码 (default：启动后交互式输入)
  --prompt PROMPT       密码提示信息
  --info INFO           查看提示信息

计算输出文件的sha值:
  --sha-file FILENAME   哈希值输出到文件(default: stderr)
  --md5                 输出文件同时计算 md5
  --sha1                输出文件同时计算 sha1
  --sha224              输出文件同时计算 sha224
  --sha256              输出文件同时计算 default: sha256
  --sha384              输出文件同时计算 sha384
  --sha512              输出文件同时计算 sha512
  --blake2b             输出文件同时计算 blake2b
  --sha-all             计算所有哈希值

切割输出文件:
  --split SPLIT         单个文件最大大小(单位：B, K, M, G, T, P。 例如: --split 256M)
  --suffix SUFFIX       指定切割文件后缀(default: 00 开始

Author: calllivecn <calllivecn@outlook.com>, Version: 0.9.8 Repositories: https://github.com/calllivecn/tar.py
```
