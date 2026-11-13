"""领域资料及现有接口核对。"""
import json,tempfile,unittest
from pathlib import Path
from warehouse.objects import ObjectStore
from warehouse.envelope import inspect

class DomainTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.store=ObjectStore(self.root/'objects')
        self.data=json.loads(Path('data/source.json').read_text(encoding='utf-8'))
    def test_existing_reader(self):
        result=inspect(self.data,self.store,self.root)
        self.assertTrue(result)

    def test_context_and_authentication(self):
        import os
        from warehouse.envelope import KeyService,seal,read
        s=KeyService({'m':os.urandom(32)});e=seal(self.store,s,'tenant','a',b'abc','m','op')
        self.assertEqual(read(self.store,s,e,'tenant','a'),b'abc')
        with self.assertRaises(ValueError):read(self.store,s,e,'other','a')
        tampered=dict(e,object_id='b')
        with self.assertRaises(ValueError):read(self.store,s,tampered,'tenant','b')
    def test_key_operation_binding(self):
        import os
        from warehouse.envelope import KeyService
        s=KeyService({'m':os.urandom(32)});dek=os.urandom(32);c={'tenant':'a'}
        self.assertEqual(s.wrap('m',dek,c,'op'),s.wrap('m',dek,c,'op'))
        with self.assertRaises(ValueError):s.wrap('m',os.urandom(32),c,'op')
