# 类似 tar 工具

## 一般用法

```shell
usage: tar.py [option] [file ... or directory ...]

POXIS tar 工具 + zstd + AES加密 + sha计算 + split大文件分割

例子:
    tar.py -cf archive.tar foo bar                # 把 foo 和 bar 文件打包为 archive.tar 文件。
    tar.py -zcf archive.tar.zst foo bar           # 把 foo 和 bar 文件打包为 archive.tar.zst 文件。
    tar.py -tvf archive.tar                       # 列出 archive.tar 里面的文件，-v 选项，列出详细信息。
    tar.py -xf archive.tar                        # 解压 archive.tar 全部文件到当前目录。
    tar.py -ecf archive.tar                       # 打包 archive.tar 后同时加密。
    tar.py -ezcf archive.tar.zst                  # 打包 archive.tar.zst 后同时加密。
    tar.py --info archive.ta                      # 查看提示信息,如果有的话。

    tar.py -c --split archinve_dir/ foo bar       # 把 foo 和 bar 文件打包为 archinve_dir/ 目录下的切割文件。
    tar.py -zvc --split archinve_dir/ foo bar     # 把 foo 和 bar 文件打包+压缩为 archinve_dir/ 目录下的切割文件。
    tar.py -ezvc --split archinve_dir/ foo bar    # 把 foo 和 bar 文件打包+压缩+加密为 archinve_dir/ 目录下的切割文件。

    tar.py -vx --split archinve_dir/              # 解压目录 archinve_dir/ 目录下的切割文件。
    tar.py -zvx --split archinve_dir/             # 解压目录 archinve_dir/ 目录下的切割文件。
    tar.py -ezvx --split archinve_dir/            # 解压目录 archinve_dir/ 目录下的切割文件。

    tar.py --info archive_dir/data.ta.0          # 查看提示信息,如果有的话

    使用-t查看文件内容时:
    如果文件后缀是(".tar.zst", ".tar.aes", ".tar.zst.aes", ".tz", ".ta", ".tza")需要指定对应的-z 或者 -e 参数。
    解压 *.tar.gz *.tar.xz *.tar.bz2 时，不要指定 -z 和 -e。

位置参数:
  target                文件s | 目录s

通用选项:
  -h, --help            输出帮助信息
  -f F                  archive 文件, 没有这参数时，默认使用标准输入输出。
  -C C                  解压输出目录(default: .)
  -O                    解压文件时输出 标准输出。创建文件时从 标准输入 读取。
  -c                    创建tar文件
  -x                    解压tar文件
  -t, --list            输出tar文件内容
  --safe-extract        解压时处理tar里不安全的路径
  -v, --verbose         输出详情
  -d, --debug           输出debug详情信息
  --excludes PATTERN [PATTERN ...]
                        排除这类文件,使用Unix shell: PATTERN

压缩选项:
  只使用zstd压缩方案, 但可以解压 *.tar.gz, *.tar.bz2, *.tar.xz。

  -z                    使用zstd压缩(default: level=3)
  -l level              指定压缩level: 1 ~ 22
  -T threads            默认使用CPU物理/2的核心数，最大8个线程。

加密:
  使用aes-256系列加密算法

  -e                    加密
  -k PASSWORK           指定密码 (default：启动后交互式输入)
  --prompt PROMPT       密码提示信息
  --info INFO           查看加密提示信息

计算输出文件的sha值:
  --sha-file FILENAME   哈希值输出到文件(default: stderr)
  --md5                 输出文件同时计算 md5
  --sha1                输出文件同时计算 sha1
  --sha224              输出文件同时计算 sha224
  --sha256              输出文件同时计算 default: sha256
  --sha384              输出文件同时计算 sha384
  --sha512              输出文件同时计算 sha512
  --blake2b             输出文件同时计算 blake2b
  --sha-all             计算以上所有哈希值

切割输出文件:
  
      在创建时分害会创建这里提供的目录。把文件名从-z -e这里生成。
      会根据 -z 和 -e 选项来生成对应后缀*.tar|*.t, *.tz, *.ta, *.tza
      当没有指定--sha-file时，会输出到--split 目录下名为: sha.txt
      

  --split SPLIT         切割时的输出目录 或者是 合并时的输入目录 (default: .)
  --split-size SPLIT_SIZE
                        单个文件最大大小(单位：B, K, M, G, T, P。 默认值：1G)
  --split-prefix SPLIT_PREFIX
                        指定切割文件的前缀(default: data.tar) 其他几种: *.tar|*.t, *.tz,
                        *.ta, *.tza
  --split-sha           计算切割文件的sha值(通过前面的sha系列指定算法)。(default: sha256)

Author: calllivecn <calllivecn@outlook.com>, Version: 0.10.0 Repositories: https://github.com/calllivecn/tar.py
```