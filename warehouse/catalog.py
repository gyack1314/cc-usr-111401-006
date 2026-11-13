"""本地目录引用的比较更新及持久写入。

引用文件是一张扁平的名字到对象摘要的映射。比较更新在锁内重新读取，因此
并发写入不会静默覆盖；每次写入都先落到同目录的临时文件并 fsync，再用
os.replace 原子替换。
"""
from pathlib import Path
import os, json, tempfile
from contextlib import contextmanager
from .objects import encode


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


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
        while True:
            try:
                fd = os.open(lock, os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
                break
            except FileExistsError:
                # 进程在持锁时崩溃会留下锁文件；持锁者已死则清理后重试。
                try:
                    owner = int(lock.read_text().strip() or '0')
                except (OSError, ValueError):
                    owner = 0
                if owner and _alive(owner):
                    raise
                try:
                    lock.unlink()
                except FileNotFoundError:
                    pass
        try:
            os.write(fd, b'%d' % os.getpid())
            yield
        finally:
            os.close(fd)
            try:
                lock.unlink()
            except FileNotFoundError:
                pass

    def _write(self, refs):
        fd, path = tempfile.mkstemp(dir=self.root, prefix='.refs-')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encode(refs)); stream.flush(); os.fsync(stream.fileno())
            os.replace(path, self.file)
        finally:
            if os.path.exists(path): os.unlink(path)

    def compare_update(self, name, expected, value):
        with self.locked():
            refs = self.read()
            if refs.get(name) != expected:
                raise ValueError('目录引用已改变')
            refs[name] = value
            self._write(refs)
        return value

    def compare_update_many(self, expected, changes):
        """在同一个锁内核对多个期望值后一次性写入，用于目录切换与旧版本保留。"""
        with self.locked():
            refs = self.read()
            for name, value in expected.items():
                if refs.get(name) != value:
                    raise ValueError('目录引用已改变')
            refs.update(changes)
            self._write(refs)
        return dict(changes)

    def compare_remove(self, name, expected):
        """仅当引用仍是 expected 时删除，返回被删除的摘要。"""
        with self.locked():
            refs = self.read()
            if refs.get(name) != expected:
                raise ValueError('目录引用已改变')
            del refs[name]
            self._write(refs)
        return expected

    def snapshot(self):
        """锁内读取一致快照，供退休审计遍历。"""
        with self.locked():
            return dict(self.read())
