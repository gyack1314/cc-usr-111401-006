"""本地目录引用的比较更新及持久写入。"""
from pathlib import Path
import os, json, tempfile
from contextlib import contextmanager
from .objects import encode

class Catalog:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.file = self.root/'refs.json'

    def read(self):
        return json.loads(self.file.read_bytes()) if self.file.exists() else {}

    @contextmanager
    def locked(self):
        lock = self.root/'.refs.lock'
        fd = os.open(lock, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
        try:
            yield
        finally:
            os.close(fd)
            lock.unlink()

    def compare_update(self, name, expected, value):
        with self.locked():
            refs = self.read()
            if refs.get(name) != expected:
                raise ValueError('目录引用已改变')
            refs[name] = value
            fd, path = tempfile.mkstemp(dir=self.root, prefix='.refs-')
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(encode(refs)); stream.flush(); os.fsync(stream.fileno())
                os.replace(path, self.file)
            finally:
                if os.path.exists(path): os.unlink(path)
        return value
