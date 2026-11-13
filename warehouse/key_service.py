"""本地密钥服务的认证包装及幂等回执。"""
import os, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .objects import encode

def b64(raw):return base64.b64encode(raw).decode('ascii')
def unb64(text):return base64.b64decode(text,validate=True)

class KeyService:
    def __init__(self,masters):self.masters=masters;self.receipts={};self.fail_at=None;self.calls=0
    def _call(self):
        self.calls+=1
        if self.calls==self.fail_at:raise ConnectionError('密钥服务暂不可用')
    def wrap(self,key_id,dek,context,operation):
        self._call();identity=hashlib.sha256(encode([key_id,context,b64(dek)])).hexdigest()
        if operation in self.receipts:
            saved=self.receipts[operation]
            if saved[0]!=identity:raise ValueError('操作身份内容冲突')
            return saved[1]
        nonce=os.urandom(12);wrapped=AESGCM(self.masters[key_id]).encrypt(nonce,dek,encode(context))
        result={'key_id':key_id,'nonce':b64(nonce),'wrapped_key':b64(wrapped),'context':context}
        self.receipts[operation]=(identity,result);return result
    def unwrap(self,envelope,context):
        self._call()
        if envelope['context']!=context:raise ValueError('包装上下文不符')
        return AESGCM(self.masters[envelope['key_id']]).decrypt(unb64(envelope['nonce']),unb64(envelope['wrapped_key']),encode(context))

