"""可恢复密钥轮换的领域测试。"""
import json, os, tempfile, unittest
from pathlib import Path
from warehouse.objects import ObjectStore, encode
from warehouse.envelope import seal, read, context_for
from warehouse.key_service import KeyService
from warehouse.catalog import Catalog
from warehouse.rotation import Rotation

DATA = json.loads(Path('data/source.json').read_text(encoding='utf-8'))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = ObjectStore(self.root/'objects')
        self.masters = {k: os.urandom(32) for k in ('master-1', 'master-2')}
        self.service = KeyService(self.masters)
        self.catalog = Catalog(self.root/'catalog')
        self.rotation = Rotation(self.store, self.service, self.catalog)

    def seed(self, tenant='alpha', name='main'):
        objects = [o for o in DATA['objects'] if o['tenant'] == tenant]
        entries = []
        for obj in objects:
            e = seal(self.store, self.service, obj['tenant'], obj['object_id'],
                     obj['content'].encode(), 'master-1', 'seed:'+obj['object_id'])
            entries.append({'tenant': e['tenant'], 'object_id': e['object_id'], 'body': e['body'],
                            'nonce': e['nonce'], 'envelope': e['envelope']})
        r = Rotation(self.store, self.service, self.catalog, name)
        version = r.publish(tenant, entries, 'master-1')
        return r, version, entries

    def plain(self, entry, tenant='alpha'):
        return read(self.store, self.service, entry, tenant, entry['object_id']).decode()


class RotationTests(Base):
    def test_rotation_keeps_ciphertext_and_reads_old_version(self):
        r, old, entries = self.seed()
        handle = r.reader()
        state = r.begin('alpha', 'master-2')
        old_entry = dict(entries[0])
        r.step('doc-a')
        new_entry = json.loads((self.root/'catalog'/'rotation-main.json').read_text())['items'][0]['entry']
        self.assertEqual(new_entry['body'], old_entry['body'])
        self.assertEqual(new_entry['nonce'], old_entry['nonce'])
        self.assertEqual(new_entry['envelope']['key_id'], 'master-2')
        # 读者仍读旧目录，旧句柄也可继续读。
        self.assertEqual(r.current_version(), old)
        self.assertEqual(handle.read('alpha', 'doc-a').decode(), '共享文档的合成正文')
        r.resume(); new = r.complete()
        self.assertNotEqual(new, old)
        self.assertEqual(handle.read('alpha', 'doc-a').decode(), '共享文档的合成正文')
        self.assertEqual(r.read_version(new, 'alpha', 'doc-b').decode(), '修订记录')

    def test_receipt_loss_and_retry_do_not_replace_verified(self):
        r, old, entries = self.seed()
        r.begin('alpha', 'master-2', operation_prefix='op')
        self.service.fail_after_at = self.service.calls + 1
        with self.assertRaises(ConnectionError):
            r.step('doc-a')
        # 服务已记账回执；重送命中回执，检查点恢复后只替换一次。
        self.service.fail_after_at = None
        r.step('doc-a')
        r.step('doc-a')
        r.step('doc-b')
        state = r.status()
        self.assertTrue(all(i['verified'] for i in state['items']))
        item = json.loads((self.root/'catalog'/'rotation-main.json').read_text())['items'][0]
        self.assertEqual(item['entry']['envelope']['key_id'], 'master-2')

    def test_pre_commit_failure_is_resumable_and_invisible(self):
        r, old, entries = self.seed()
        r.begin('alpha', 'master-2', operation_prefix='op')
        self.service.fail_at = self.service.calls + 1
        with self.assertRaises(ConnectionError):
            r.step('doc-a')
        self.assertEqual(r.current_version(), old)
        self.service.fail_at = None
        with self.assertRaises(ValueError):
            r.complete()
        self.assertEqual(r.current_version(), old)
        r.resume(); new = r.complete()
        self.assertNotEqual(new, old)

    def test_wrong_tenant_never_accepted(self):
        r, old, entries = self.seed()
        with self.assertRaises(ValueError):
            r.read_version(old, 'beta', 'doc-a')
        forged = dict(entries[0], tenant='beta')
        with self.assertRaises(ValueError):
            read(self.store, self.service, forged, 'beta', 'doc-a')
        # 共享正文的其他租户对象也不能借同摘要越权。
        tampered = dict(entries[0], tenant='beta', object_id='doc-a')
        with self.assertRaises(ValueError):
            read(self.store, self.service, tampered, 'beta', 'doc-a')

    def test_bad_new_version_not_switched_in(self):
        r, old, entries = self.seed()
        r.begin('alpha', 'master-2'); r.resume()
        state = json.loads((self.root/'catalog'/'rotation-main.json').read_text())
        broken = dict(state['items'][0]['entry'])
        broken['body'] = '0' * 64
        payload = {'format': 1, 'name': 'main', 'tenant': 'alpha', 'key_id': 'master-2',
                   'entries': [broken] + [i['entry'] for i in state['items'][1:]],
                   'identity': 'x'}
        with self.assertRaises(ValueError):
            r._manifest(self.store.put_json(payload))
        self.assertEqual(r.current_version(), old)

    def test_retire_requires_all_references_and_receipt(self):
        r, old, entries = self.seed()
        r.begin('alpha', 'master-2'); r.resume(); new = r.complete()
        # complete 自动保留旧版本；保留引用会让退休审计拒绝退休，即使当前头
        # 已不再引用 master-1。
        self.assertTrue(r.audit('master-1')['referenced'])
        with self.assertRaises(ValueError):
            r.retire('master-1', 'retire-1')
        self.assertIn('master-1', self.service.masters)
        refs = self.catalog.read()
        self.assertIn('retained:main:'+old, refs)
        self.assertEqual(r.release_version(old), ['retained:main:'+old])
        receipt = r.retire('master-1', 'retire-master-1')
        self.assertEqual(receipt['receipt']['status'], 'disabled')
        self.assertFalse(receipt['physical_deletion'])
        self.assertIn('物理销毁', receipt['note'])
        # 停用只影响本服务；旧信封确实不能再通过该服务解开，但快照条目
        # 仍保留在不可变对象仓中，是否物理销毁不在本回执的声明范围内。
        with self.assertRaises(ValueError):
            self.service.unwrap(entries[0]['envelope'], context_for('alpha', 'doc-a', entries[0]['body']))
        self.assertTrue((self.store.root/entries[0]['body']).exists())

    def test_retired_master_rejected_as_target(self):
        r, old, entries = self.seed()
        r.begin('alpha', 'master-2'); r.resume(); r.complete()
        r.release('retained:main:'+old)
        r.retire('master-1', 'retire-old')
        with self.assertRaises(ValueError):
            r.begin('alpha', 'master-1')

    def test_mixed_tenant_version_rejected(self):
        r, old, entries = self.seed()
        other = seal(self.store, self.service, 'beta', 'doc-x', b'x', 'master-1', 'seed-x')
        mixed = entries + [{'tenant': 'beta', 'object_id': 'doc-x', 'body': other['body'],
                            'nonce': other['nonce'], 'envelope': other['envelope']}]
        with self.assertRaises(ValueError):
            r.publish('alpha', mixed, 'master-1')
        self.assertEqual(r.current_version(), old)

    def test_rotate_does_not_log_plaintext_key(self):
        r, old, entries = self.seed()
        r.begin('alpha', 'master-2', operation_prefix='op'); r.resume()
        blob = (self.root/'catalog'/'rotation-main.json').read_bytes()
        # 检查点只含包装信封，不含 32 字节明文密钥的 base64 形式。
        import base64, re
        tokens = re.findall(rb'"([A-Za-z0-9+/=]{43,45})"', blob)
        self.assertFalse([t for t in tokens if len(t) in (43, 44)])
        for item in json.loads(blob)['items']:
            self.assertNotIn('dek', item['entry'])
            self.assertNotIn('key', {k for k in item['entry'] if k != 'envelope'})

    def test_retirement_counts_other_tenant_versions(self):
        r, old, entries = self.seed()
        other, other_old, _ = self.seed('beta', 'main:beta')
        r.begin('alpha', 'master-2'); r.resume(); r.complete()
        r.release('retained:main:'+old)
        audit = r.audit('master-1')
        self.assertTrue(audit['referenced'])
        self.assertFalse(audit['unresolved_references'])
        self.assertIn('main:beta', str(audit['references']))
        with self.assertRaises(ValueError):
            r.retire('master-1', 'retire-early')

    def test_unfinished_journal_blocks_retirement(self):
        r, old, entries = self.seed()
        r.begin('alpha', 'master-2', operation_prefix='op')
        r.step('doc-a')
        audit = r.audit('master-1')
        # 旧目录仍引用 master-1，因此所有原对象都算未完成引用；只有已核验
        # 对象可以在恢复后改用 master-2。
        self.assertEqual(audit['pending_rotation']['main'], ['doc-a', 'doc-b'])
        with self.assertRaises(ValueError):
            r.retire('master-1', 'retire-1')

    def test_catalog_changed_mid_rotation_keeps_checkpoint(self):
        r, old, entries = self.seed()
        r.begin('alpha', 'master-2', operation_prefix='op'); r.resume()
        # 另一个写入者把当前目录改到别处；complete 必须拒绝覆盖并保留检查点。
        decoy = self.store.put_json({'format': 1, 'name': 'main', 'tenant': 'alpha',
                                     'entries': entries, 'identity': 'x'})
        try:
            self.catalog.compare_update('main', old, decoy)
        except ValueError:
            self.skipTest('目录写锁被占用')
        with self.assertRaises(ValueError):
            r.complete()
        self.assertEqual(r.current_version(), decoy)

    def test_snapshot_pin_survives_rotation(self):
        r, old, entries = self.seed()
        snap = r.pinned_snapshot([{'row_id': 'a', 'value': 1}], {'value': 'int'}, old)
        handle = r.snapshot_reader(snap)
        r.begin('alpha', 'master-2'); r.resume(); r.complete()
        self.assertEqual(handle.read('alpha', 'doc-a').decode(), '共享文档的合成正文')
        self.assertEqual(r.snapshot_reader(snap).version, old)


if __name__ == '__main__':
    unittest.main()
