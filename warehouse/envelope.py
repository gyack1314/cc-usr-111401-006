"""租户对象的首次认证加密和读取。"""
from .key_service import KeyService,b64,unb64
from .objects import encode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def seal(store,service,tenant,object_id,raw,key_id,operation):
    aad={'tenant':tenant,'object_id':object_id};dek=os.urandom(32);nonce=os.urandom(12)
    body=store.put(AESGCM(dek).encrypt(nonce,raw,encode(aad)));context=dict(aad,body=body)
    return dict(aad,body=body,nonce=b64(nonce),envelope=service.wrap(key_id,dek,context,operation))

def read(store,service,entry,tenant,object_id):
    aad={'tenant':tenant,'object_id':object_id};context=dict(aad,body=entry['body'])
    if entry['tenant']!=tenant or entry['object_id']!=object_id:raise ValueError('对象归属不符')
    dek=service.unwrap(entry['envelope'],context)
    return AESGCM(dek).decrypt(unb64(entry['nonce']),store.get(entry['body']),encode(aad))

def inspect(data,store,root):
    service=KeyService({k:os.urandom(32) for k in data['keys']});entries=[]
    for obj in data['objects']:
        e=seal(store,service,obj['tenant'],obj['object_id'],obj['content'].encode(),data['keys'][0],obj['object_id'])
        assert read(store,service,e,obj['tenant'],obj['object_id']).decode()==obj['content']
        entries.append({'tenant':e['tenant'],'object_id':e['object_id'],'body':e['body'],'key_id':e['envelope']['key_id']})
    return {'objects':entries,'service_calls':service.calls}
