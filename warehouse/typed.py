"""保留类型差异的关系键编码。"""
from .objects import encode

def typed(value):
    if value is None:return ['null']
    if isinstance(value,bool):return ['bool',value]
    if isinstance(value,int):return ['int',str(value)]
    if isinstance(value,str):return ['str',value]
    if isinstance(value,(list,tuple)):return ['tuple',[typed(x) for x in value]]
    raise ValueError('键类型不支持')

def key(value):return encode(typed(value))
