"""完整行快照的冻结读取和字段目录。"""
from .objects import ObjectStore

class Snapshots:
    def __init__(self, store): self.store=store

    def create(self, rows, schema):
        identities=set()
        for row in rows:
            if not isinstance(row,dict) or not isinstance(row.get('row_id'),str):
                raise ValueError('行缺少身份')
            if row['row_id'] in identities: raise ValueError('行身份重复')
            identities.add(row['row_id'])
        data=self.store.put_json(rows)
        return self.store.put_json({'format':1,'schema':schema,'data':data,'rows':len(rows)})

    def read(self, digest):
        manifest=self.store.json(digest)
        if manifest['format']!=1: raise ValueError('快照格式不支持')
        rows=self.store.json(manifest['data'])
        if len(rows)!=manifest['rows']: raise ValueError('快照行数不符')
        identities=[r['row_id'] for r in rows]
        if len(set(identities))!=len(identities): raise ValueError('快照行身份重复')
        return {'snapshot':digest,'schema':manifest['schema'],'rows':rows}
