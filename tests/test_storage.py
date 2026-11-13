"""既有对象及目录接口的边界检查。"""
import tempfile, unittest
from pathlib import Path
from warehouse.objects import ObjectStore
from warehouse.catalog import Catalog
from warehouse.snapshot import Snapshots
from warehouse.typed import key

class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.store=ObjectStore(self.root/'objects')
    def test_roundtrip(self):
        digest=self.store.put_json({'值':None,'rows':[1,2]})
        self.assertEqual(self.store.json(digest),{'值':None,'rows':[1,2]})
        self.assertEqual(self.store.put_json({'rows':[1,2],'值':None}),digest)
    def test_bad_identity(self):
        with self.assertRaises(ValueError):self.store.get('../refs.json')
    def test_corruption(self):
        digest=self.store.put(b'abc');(self.store.root/digest).write_bytes(b'abd')
        with self.assertRaises(ValueError):self.store.get(digest)
    def test_catalog_conflict(self):
        c=Catalog(self.root/'catalog');c.compare_update('main',None,'a')
        with self.assertRaises(ValueError):c.compare_update('main',None,'b')
        self.assertEqual(c.read(),{'main':'a'})
    def test_snapshot_frozen(self):
        s=Snapshots(self.store);old=s.create([{'row_id':'a','value':1}],{'value':'int'})
        new=s.create([{'row_id':'a','value':2}],{'value':'int'})
        self.assertEqual(s.read(old)['rows'][0]['value'],1)
        self.assertNotEqual(old,new)
    def test_duplicate_rows(self):
        with self.assertRaises(ValueError):Snapshots(self.store).create([{'row_id':'a'},{'row_id':'a'}],{})
    def test_typed_key(self):
        self.assertEqual(len({key(None),key(''),key(1),key(True),key('1')}),5)
