"""本地密钥服务的认证包装、幂等回执及主密钥停用。

服务自身只持有主密钥；包装结果只含密文包装和非秘密身份，不含数据密钥。
所有会产生副作用的操作都以调用方提供的操作 ID 记账：重送同一操作返回同一
回执，操作 ID 被用于不同内容时拒绝执行。
"""
import os, base64, hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from .objects import encode

def b64(raw):return base64.b64encode(raw).decode('ascii')
def unb64(text):return base64.b64decode(text,validate=True)


def load_runtime_masters(root, key_ids):
    """在未跟踪的运行目录中载入或生成主密钥（仅限本地开发实例）。

    主密钥只落在这个不入库、权限收紧的目录里；目录版本、检查点和日志都
    不包含明文密钥。文件按内容寻址无关的 key_id 命名，绝不写进资料仓。
    """
    root = Path(root)/'keys'
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    masters = {}
    for key_id in key_ids:
        if not isinstance(key_id, str) or not key_id or '/' in key_id or '\\' in key_id:
            raise ValueError('主密钥身份非法')
        path = root/key_id
        if path.exists():
            raw = path.read_bytes()
            if len(raw) != 32:
                raise ValueError('运行目录中的主密钥长度不符')
            masters[key_id] = raw
        else:
            raw = os.urandom(32)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, raw); os.fsync(fd)
            finally:
                os.close(fd)
            masters[key_id] = raw
    return masters


class KeyService:
    def __init__(self,masters):
        self.masters=masters
        self.receipts={}
        self.fail_at=None
        self.fail_after_at=None
        self.calls=0
        self.disabled=set()
        self.retirement_receipts={}

    def _call(self):
        self.calls+=1
        # fail_at: 副作用发生前失联，可安全重送。
        if self.calls==self.fail_at:raise ConnectionError('密钥服务暂不可用')
        return self.calls==self.fail_after_at

    def _lost(self, lost):
        # fail_after_at: 副作用已记账但调用方没有收到回执，重送必须命中回执。
        if lost:raise ConnectionError('密钥服务回执丢失')

    def _operation_identity(self, action, key_id, context=None, material=None):
        payload=[action,key_id,context,material]
        return hashlib.sha256(encode(payload)).hexdigest()

    def wrap(self,key_id,dek,context,operation):
        lost=self._call()
        if key_id in self.disabled:raise ValueError('主密钥已停用')
        identity=self._operation_identity('wrap',key_id,context,b64(dek))
        if operation in self.receipts:
            saved=self.receipts[operation]
            if saved[0]!=identity:raise ValueError('操作身份内容冲突')
            self._lost(lost)
            return saved[1]
        if key_id not in self.masters:raise ValueError('主密钥身份未知')
        nonce=os.urandom(12);wrapped=AESGCM(self.masters[key_id]).encrypt(nonce,dek,encode(context))
        result={'key_id':key_id,'nonce':b64(nonce),'wrapped_key':b64(wrapped),'context':context}
        self.receipts[operation]=(identity,result)
        self._lost(lost)
        return result

    def unwrap(self,envelope,context):
        lost=self._call()
        if envelope['key_id'] in self.disabled:raise ValueError('主密钥已停用')
        if envelope['context']!=context:raise ValueError('包装上下文不符')
        try:
            raw=AESGCM(self.masters[envelope['key_id']]).decrypt(
                unb64(envelope['nonce']),unb64(envelope['wrapped_key']),encode(context))
        except KeyError:raise ValueError('主密钥身份未知')
        except InvalidTag:raise ValueError('包装认证失败：主密钥、上下文或回执不符')
        self._lost(lost)
        return raw

    def receipt(self, operation, kind='wrap'):
        """只读取既有回执，不产生副作用；返回 None 表示该操作尚未记账。"""
        table = self.retirement_receipts if kind=='retire' else self.receipts
        saved = table.get(operation)
        return None if saved is None else saved[1]

    def retire(self,key_id,operation):
        """停用主密钥并返回可核对的服务回执。

        回执只代表本服务的停用动作，不证明任何外部备份、快照或副本已被物理
        销毁；调用方不得据此作过量声明。
        """
        lost=self._call()
        identity=self._operation_identity('retire',key_id)
        if operation in self.retirement_receipts:
            saved=self.retirement_receipts[operation]
            if saved[0]!=identity:raise ValueError('操作身份内容冲突')
            self._lost(lost)
            return saved[1]
        if key_id not in self.masters:raise ValueError('主密钥身份未知')
        self.disabled.add(key_id)
        result={'key_id':key_id,'action':'retire','status':'disabled',
                'scope':'local_service_only'}
        self.retirement_receipts[operation]=(identity,result)
        self._lost(lost)
        return result
