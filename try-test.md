# 实现过程中的设想，测试，遇到的问题，和解决方案。


```s
怎么实现一种管道式的处理流?

实现像类似shell 管理 的处理的效果，处其他处理可以，随机需要增加，或减少。
tar() | zstd() | aes() | --> hash() --> sha result --> end()
                       \
                        \ --> split() -- > file result --> end()
```

- tarfile.open() 需要 fileobj 需要包装一下。
- pipe 是两个FD 需要 关闭两次。 写关闭时: read() -> b""

```py
class PIPE:

    def __init__(self):
        self.r, self.w = os.pipe()
    
    def read(self, size):
        return os.read(self.r, size)

    def write(self, data):
        return os.write(self.w, data)
    
    def close(self):
        os.close(self.w)
    
    def close2(self):
        os.close(self.r)
```
