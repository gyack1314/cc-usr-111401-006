"""租户对象的首次认证加密、读取和包装轮换。"""
from .key_service import KeyService,b64,unb64
from .objects import encode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import hmac, os


def context_for(tenant, object_id, body):
    """返回包装上下文；正文摘要也被认证。"""
    return {'tenant': tenant, 'object_id': object_id, 'body': body}


def _aad(tenant, object_id):
    return {'tenant': tenant, 'object_id': object_id}


def _check_entry(entry, tenant, object_id):
    """在调用密钥服务之前显式核对租户、对象身份和包装上下文。

    解密成功本身不能证明对象属于请求的租户：共享正文或复制元数据都可能
    让相邻租户的密文仍可解开。因此归属检查必须独立于 AES-GCM 标签。
    """
    if not isinstance(entry, dict):
        raise ValueError('对象条目结构不符')
    if entry.get('tenant') != tenant or entry.get('object_id') != object_id:
        raise ValueError('对象归属不符')
    body = entry.get('body')
    if not isinstance(body, str):
        raise ValueError('对象正文身份不符')
    envelope = entry.get('envelope')
    if not isinstance(envelope, dict):
        raise ValueError('对象包装结构不符')
    if envelope.get('context') != context_for(tenant, object_id, body):
        raise ValueError('包装上下文不符')
    return body


def _authenticated_open(dek, nonce, ciphertext, tenant, object_id):
    try:
        return AESGCM(dek).decrypt(unb64(nonce), ciphertext, encode(_aad(tenant, object_id)))
    except InvalidTag:
        raise ValueError('对象认证失败：租户、身份或正文不符')


def _decrypt(store, service, entry, tenant, object_id):
    body = _check_entry(entry, tenant, object_id)
    dek = service.unwrap(entry['envelope'], context_for(tenant, object_id, body))
    return _authenticated_open(dek, entry['nonce'], store.get(body), tenant, object_id)


def seal(store,service,tenant,object_id,raw,key_id,operation):
    aad=_aad(tenant, object_id);dek=os.urandom(32);nonce=os.urandom(12)
    body=store.put(AESGCM(dek).encrypt(nonce,raw,encode(aad)));context=context_for(tenant,object_id,body)
    return dict(aad,body=body,nonce=b64(nonce),envelope=service.wrap(key_id,dek,context,operation))


def read(store,service,entry,tenant,object_id):
    return _decrypt(store, service, entry, tenant, object_id)


def verify(store, service, entry, tenant, object_id):
    """读取并认证对象；返回正文，供轮换前后逐字节核对。"""
    return _decrypt(store, service, entry, tenant, object_id)


def rotate(store,service,entry,tenant,object_id,key_id,operation):
    """用新的主密钥重新包装文件密钥，不改写正文、nonce 或 AAD。

    旧包装先被解开；新回执写入前会用原正文校验新包装，确保包装上下文
    和文件密钥都没有被替换成另一份内容。明文密钥只存在于本次调用栈。
    """
    body = _check_entry(entry, tenant, object_id)
    context = context_for(tenant, object_id, body)
    dek = service.unwrap(entry['envelope'], context)
    ciphertext = store.get(body)
    plaintext = _authenticated_open(dek, entry['nonce'], ciphertext, tenant, object_id)
    envelope = service.wrap(key_id, dek, context, operation)
    if not isinstance(envelope, dict) or envelope.get('key_id') != key_id:
        raise ValueError('新包装的主密钥身份不符')
    if envelope.get('context') != context:
        raise ValueError('新包装的上下文不符')
    rewritten = _authenticated_open(
        service.unwrap(envelope, context), entry['nonce'], ciphertext, tenant, object_id
    )
    if not hmac.compare_digest(rewritten, plaintext):
        raise ValueError('新包装未能还原同一正文')
    return {'tenant': tenant, 'object_id': object_id, 'body': body,
            'nonce': entry['nonce'], 'envelope': envelope}


def inspect(data,store,root):
    service=KeyService({k:os.urandom(32) for k in data['keys']});entries=[]
    for obj in data['objects']:
        e=seal(store,service,obj['tenant'],obj['object_id'],obj['content'].encode(),data['keys'][0],obj['object_id'])
        assert read(store,service,e,obj['tenant'],obj['object_id']).decode()==obj['content']
        entries.append({'tenant':e['tenant'],'object_id':e['object_id'],'body':e['body'],'key_id':e['envelope']['key_id']})
    return {'objects':entries,'service_calls':service.calls}
