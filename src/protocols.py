
from typing import (
    cast,
    Protocol,
)

class ReadWrite(Protocol):
    def read(self, size: int) -> bytes: ...
    def write(self, data: bytes) -> int: ...
    def close(self) -> None: ...
