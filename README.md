# 类似 tar 工具

## 处理工作流:

```py
# 工作方式类似shell管道的处理的效果, 根据需要增加，或减少处理步骤。
tar() | zstd() | encrypt() --> file result
                            \ --> hash() --> sha result
                             \ # 或者输出使用文件切割
                              \ --> split() -- > files result

# 解压
decrypt() | zstd() | tar() --> files result

mrege() | decrypt() | zstd() | tar() --> files result
```