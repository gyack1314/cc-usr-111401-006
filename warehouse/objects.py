"""不可变对象的摘要寻址与完整性读取。"""
from pathlib import Path
import hashlib, json, os, tempfile

def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

class ObjectStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, raw):
        if not isinstance(raw, bytes):
            raise TypeError('对象必须是字节')
        digest = hashlib.sha256(raw).hexdigest()
        target = self.root / digest
        if target.exists():
            if self.get(digest) != raw:
                raise ValueError('同摘要内容冲突')
            return digest
        fd, name = tempfile.mkstemp(dir=self.root, prefix='.writing-')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return digest

    def get(self, digest):
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('对象身份非法')
        raw = (self.root / digest).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('对象摘要不符')
        return raw

    def put_json(self, value):
        return self.put(encode(value))

    def json(self, digest):
        return json.loads(self.get(digest))
