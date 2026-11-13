"""可续作的密钥轮换管理。

轮换只重做文件密钥的包装信封，正文密文、nonce 和认证附加数据保持原样。
每完成一个对象就原子更新检查点；临时故障、密钥服务重送和“已记账但回执
丢失”都可以从最后一个已核验的包装继续，不会重复替换已核验的包装。

目录版本是读者看到的唯一提交点：轮换期间 ``main`` 继续指向旧版本，新版本
只有在逐对象解开并核对租户、对象摘要和包装上下文之后才切换。切换前旧版本
被显式保留在目录引用里，因此旧读句柄和保留快照仍有确定的解包路径；主密钥
只有在所有目录引用都不再使用它、且密钥服务给出停用回执之后才能退休。

检查点和目录元数据只保存包装后的信封与非秘密身份；数据密钥的明文不会写入
日志、检查点或新目录版本。
"""
import hashlib
import hmac
import json
import os
import tempfile

from .catalog import Catalog
from .envelope import context_for, read, rotate
from .objects import ObjectStore, encode

FORMAT = 1
RETIREMENT_NOTE = (
    '本回执仅表示该本地密钥服务实例不再接受此主密钥；'
    '不表示任何备份、快照副本或外部存储上的密钥材料已被物理销毁。'
)


def _identity(value):
    return hashlib.sha256(encode(value)).hexdigest()


def _content_identity(entries):
    """逻辑内容身份，不含包装信封；用于跨版本核对同一批对象。"""
    projected = []
    for entry in entries:
        missing = [k for k in ('tenant', 'object_id', 'body', 'nonce') if k not in entry]
        if missing:
            raise ValueError('目录条目缺少字段：%s' % ','.join(missing))
        projected.append({k: entry[k] for k in ('tenant', 'object_id', 'body', 'nonce')})
    return _identity(projected)


def _check_manifest(manifest, name=None):
    if not isinstance(manifest, dict):
        raise ValueError('目录版本结构不符')
    if manifest.get('format') != FORMAT:
        raise ValueError('目录版本格式不支持')
    if name is not None and manifest.get('name') != name:
        raise ValueError('目录版本身份不符')
    entries = manifest.get('entries')
    if not isinstance(entries, list) or not entries:
        raise ValueError('目录版本没有条目')
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('目录条目结构不符')
        if not isinstance(entry.get('tenant'), str) or not entry['tenant']:
            raise ValueError('目录条目租户不符')
        if not isinstance(entry.get('object_id'), str) or not entry['object_id']:
            raise ValueError('目录条目对象身份不符')
        body = entry.get('body')
        if (not isinstance(body, str) or len(body) != 64
                or any(c not in '0123456789abcdef' for c in body)):
            raise ValueError('目录条目对象摘要不符')
        if not isinstance(entry.get('nonce'), str):
            raise ValueError('目录条目 nonce 不符')
        if not isinstance(entry.get('envelope'), dict):
            raise ValueError('目录条目包装结构不符')
        if entry['envelope'].get('context') != context_for(
                entry['tenant'], entry['object_id'], body):
            raise ValueError('目录条目包装上下文不符')
    tenants = {entry['tenant'] for entry in entries}
    if len(tenants) != 1:
        raise ValueError('目录版本混入多个租户')
    if manifest.get('tenant') not in tenants:
        raise ValueError('目录版本租户不符')
    if manifest.get('identity') != _content_identity(entries):
        raise ValueError('目录版本内容身份不符')
    return manifest


def _atomic_write(path, payload):
    path = os.fspath(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or '.', prefix='.rotation-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class Reader:
    """固定在某个目录版本上的读句柄。

    句柄在打开时记下版本摘要，轮换提交之后仍按原版本解包；调用方无需知道
    当前头已经切换，也不会被新目录的一部分更新影响。
    """

    def __init__(self, rotation, version):
        self._rotation = rotation
        self.version = version

    def read(self, tenant, object_id):
        return self._rotation.read_version(self.version, tenant, object_id)


class Rotation:
    """管理一个命名目录的包装轮换、版本保留和主密钥退休判断。"""

    def __init__(self, store, service, catalog, name='main'):
        self.store = ObjectStore(store.root)
        self.service = service
        self.catalog = Catalog(catalog.root)
        self.name = name
        self.root = catalog.root
        self.journal = self.root / ('rotation-%s.json' % name)
        self.retirements = self.root / ('retirements-%s.json' % name)

    # ------------------------------------------------------------ 目录读取
    def _manifest(self, digest):
        if not isinstance(digest, str):
            raise ValueError('目录版本身份非法')
        manifest = self.store.json(digest)
        return _check_manifest(manifest, self.name)

    def current_version(self):
        refs = self.catalog.read()
        if self.name not in refs:
            raise ValueError('目录尚未发布')
        return refs[self.name]

    def reader(self, version=None):
        """打开固定在指定（默认当前）目录版本上的读句柄。"""
        return Reader(self, self.current_version() if version is None else version)

    def read_current(self, tenant, object_id):
        return self.read_version(self.current_version(), tenant, object_id)

    def snapshot_reader(self, manifest_digest):
        """返回保留快照所钉住目录版本的读句柄。

        快照清单只钉住目录版本摘要；即使当前头已切换，句柄仍解包创建时的
        包装。清单必须自称是钉住快照，避免把任意对象当作目录版本。
        """
        manifest = self.store.json(manifest_digest)
        version = manifest.get('catalog_version')
        if manifest.get('format') != 1 or not isinstance(version, str):
            raise ValueError('快照未钉住目录版本')
        pinned = self._manifest(version)
        if manifest.get('tenant') != pinned['tenant']:
            raise ValueError('快照租户与目录版本不符')
        ref = 'snapshot:%s' % manifest_digest
        if self.catalog.read().get(ref) != version:
            raise ValueError('快照未在目录中登记')
        return self.reader(version)

    def pinned_snapshot(self, rows, schema, version=None):
        """创建钉住当前目录版本的完整行快照。

        快照清单沿用 snapshot.py 的格式，只额外记录它引用的目录版本；因此
        普通快照读取仍可用，而 ``snapshot_reader`` 能把旧快照明确地解包到
        当时的目录版本，轮换切换后不会悄悄读到新包装。
        """
        pinned = self.current_version() if version is None else version
        self._manifest(pinned)
        from .snapshot import Snapshots
        digest = Snapshots(self.store).create(rows, schema)
        manifest = self.store.json(digest)
        manifest['catalog_version'] = pinned
        manifest['tenant'] = self._manifest(pinned)['tenant']
        pinned_digest = self.store.put_json(manifest)
        # 快照登记为目录引用，退休审计才能真正看到它；未释放的保留快照会
        # 阻止对应主密钥退休。重复创建同一快照是幂等的。
        ref = 'snapshot:%s' % pinned_digest
        refs = self.catalog.read()
        if ref in refs:
            if refs[ref] != pinned:
                raise ValueError('快照登记的目录版本已被改写')
        else:
            self.catalog.compare_update(ref, None, pinned)
        return pinned_digest

    def release_snapshot(self, manifest_digest):
        """释放钉住快照的目录登记；已存在的快照对象本身仍可读。"""
        ref = 'snapshot:%s' % manifest_digest
        refs = self.catalog.read()
        if ref not in refs:
            raise ValueError('快照未在目录中登记')
        return self.catalog.compare_remove(ref, refs[ref])

    def versions(self):
        """返回目录中所有目录版本引用：引用名 -> 版本摘要。

        当前头、保留版本和钉住快照都登记在同一张引用表里，因此这里不只看
        当前头。无法解释的引用会报错而不是被忽略。
        """
        refs = self.catalog.read()
        found = {}
        for ref, digest in refs.items():
            found[ref] = self._ref_version(ref, digest)
        return found

    def _ref_version(self, ref, digest):
        try:
            manifest = self.store.json(digest)
        except (OSError, ValueError, TypeError):
            raise ValueError('目录引用无法读取：%s' % ref)
        if not isinstance(manifest, dict) or manifest.get('format') != FORMAT \
                or 'entries' not in manifest:
            raise ValueError('目录引用不是可解包的目录版本：%s' % ref)
        _check_manifest(manifest)
        return digest

    def publish(self, tenant, entries, key_id=None):
        """校验并发布目录版本（用于首次发布或独立版本发布）。

        写入的新版本必须能被逐个对象完整解开，且租户、对象摘要和包装上下文
        与条目声明一致，才会切换目录引用。返回新版本摘要。
        """
        entries = [dict(e, tenant=tenant) for e in entries]
        for entry in entries:
            if entry.get('tenant') != tenant:
                raise ValueError('目录条目租户不符')
            read(self.store, self.service, entry, tenant, entry.get('object_id'))
        payload = {
            'format': FORMAT,
            'name': self.name,
            'tenant': tenant,
            'key_id': key_id if key_id is not None else self._common_key(entries),
            'entries': entries,
            'identity': _content_identity(entries),
        }
        digest = self.store.put_json(payload)
        manifest = self._manifest(digest)
        for entry in manifest['entries']:
            read(self.store, self.service, entry, tenant, entry['object_id'])
        previous = self.catalog.read().get(self.name)
        self.catalog.compare_update(self.name, previous, digest)
        return digest

    @staticmethod
    def _common_key(entries):
        keys = {e['envelope']['key_id'] for e in entries}
        return keys.pop() if len(keys) == 1 else None

    def read_version(self, version, tenant, object_id):
        """按明确的旧/新目录版本解包单个对象。

        旧读句柄只需持有版本摘要即可继续读取，即使 ``main`` 已经切换。调用
        前会核对版本租户和条目归属，不把“能解密”当作归属证明。
        """
        manifest = self._manifest(version)
        if manifest['tenant'] != tenant:
            raise ValueError('目录版本租户不符')
        for entry in manifest['entries']:
            if entry['object_id'] == object_id:
                if entry['tenant'] != tenant:
                    raise ValueError('对象归属不符')
                return read(self.store, self.service, entry, tenant, object_id)
        raise ValueError('目录版本不含该对象')

    def retain(self, ref, version=None):
        """保留一个目录版本，使旧读句柄和快照有明确引用路径。

        保留引用参与退休审计；未显式释放的保留版本会阻止对应主密钥退休。
        引用写入是原子的，并返回实际保留的版本摘要。
        """
        if not isinstance(ref, str) or not ref:
            raise ValueError('保留引用名非法')
        if ref == self.name:
            raise ValueError('不能覆盖当前目录引用')
        version = self.current_version() if version is None else version
        manifest = self._manifest(version)
        refs = self.catalog.read()
        if ref in refs and refs[ref] != version:
            raise ValueError('保留引用已指向其他版本')
        if ref not in refs:
            self.catalog.compare_update(ref, None, version)
        return version

    def release_version(self, version):
        """释放所有指向该版本的保留/快照引用；当前头不能被释放。"""
        refs = self.catalog.read()
        targets = {ref: digest for ref, digest in refs.items()
                   if digest == version and ref != self.name}
        for ref, digest in targets.items():
            self.catalog.compare_remove(ref, digest)
        return sorted(targets)

    def release(self, ref):
        """释放保留引用；释放后该版本不再阻止主密钥退休。"""
        refs = self.catalog.read()
        if ref == self.name:
            raise ValueError('不能释放当前目录引用')
        if ref not in refs:
            raise ValueError('保留引用不存在')
        return self.catalog.compare_remove(ref, refs[ref])

    # ------------------------------------------------------------ 检查点
    def _load(self):
        if not self.journal.exists():
            return None
        state = json.loads(self.journal.read_text(encoding='utf-8'))
        if state.get('format') != FORMAT:
            raise ValueError('轮换检查点格式不支持')
        if state.get('name') != self.name:
            raise ValueError('轮换检查点身份不符')
        return state

    def _save(self, state):
        _atomic_write(self.journal, json.dumps(
            state, ensure_ascii=False, sort_keys=True, separators=(',', ':')
        ).encode('utf-8'))

    def status(self):
        state = self._load()
        if state is None:
            return None
        return {
            'name': self.name,
            'tenant': state['tenant'],
            'base': state['base'],
            'target_key_id': state['target_key_id'],
            'published': state.get('published'),
            'items': [
                {'object_id': item['object_id'], 'verified': item['verified']}
                for item in state['items']
            ],
        }

    # ------------------------------------------------------------ 轮换流程
    def begin(self, tenant, key_id, entries=None, operation_prefix=None):
        """建立或恢复轮换检查点，不改变读者看到的目录。

        ``entries`` 若给出，必须与当前目录版本的逻辑内容一致；否则直接以
        当前目录版本为轮换基数。已发布完成的检查点可以被下一次轮换替换。
        """
        base = self.current_version()
        manifest = self._manifest(base)
        if manifest['tenant'] != tenant:
            raise ValueError('目录版本租户不符')
        if key_id in getattr(self.service, 'disabled', ()) or self.retirement(key_id) is not None:
            raise ValueError('目标主密钥已停用，不能作为轮换目标')
        for entry in manifest['entries']:
            if entry['envelope'].get('key_id') == key_id:
                raise ValueError('对象已使用目标主密钥，不能同密钥轮换')
        expected = manifest['entries']
        if entries is not None:
            entries = [dict(e, tenant=tenant) for e in entries]
            if _content_identity(entries) != _content_identity(expected):
                raise ValueError('轮换条目与当前目录版本不符')
            for entry in entries:
                read(self.store, self.service, entry, tenant, entry['object_id'])
            expected = entries
        state = self._load()
        if state is not None and state.get('published'):
            # 上一轮已完成；只有同一基数/目标的重送才复用，否则开始新检查点。
            if (state['base'], state['target_key_id'], state['tenant']) == (base, key_id, tenant):
                return state
            state = None
        if state is None:
            prefix = operation_prefix or '%s:%s:%s' % (self.name, base, key_id)
            state = {
                'format': FORMAT,
                'name': self.name,
                'tenant': tenant,
                'base': base,
                'target_key_id': key_id,
                'operation_prefix': prefix,
                'items': [
                    {'object_id': entry['object_id'],
                     'original': entry, 'entry': entry, 'verified': False}
                    for entry in expected
                ],
                'published': None,
            }
            self._save(state)
            return state
        if (state['tenant'], state['target_key_id'], state['base']) != (tenant, key_id, base):
            raise ValueError('轮换检查点目标不符')
        if operation_prefix not in (None, state['operation_prefix']):
            raise ValueError('轮换操作前缀与检查点不符')
        if _content_identity([item['original'] for item in state['items']]) \
                != _content_identity(expected):
            raise ValueError('轮换检查点对象集合不符')
        return state

    def _operation(self, state, object_id):
        return '%s:%s' % (state['operation_prefix'], object_id)

    def step(self, object_id):
        """替换单个对象信封并持久化；已完成核验的包装不会再次替换。"""
        state = self._load()
        if state is None or state.get('published'):
            raise ValueError('没有可续作的轮换检查点')
        item = next((i for i in state['items'] if i['object_id'] == object_id), None)
        if item is None:
            raise ValueError('对象不在轮换范围内')
        if item['verified']:
            return item['entry']
        before = item['entry']
        operation = self._operation(state, object_id)
        # 先查服务回执：若上次已记账但回执丢失，直接核验既有回执而不是再次包装。
        saved = self.service.receipt(operation)
        if saved is None:
            after = rotate(self.store, self.service, before, state['tenant'], object_id,
                           state['target_key_id'], operation)
        else:
            after = dict(before, envelope=saved)
            if after['envelope'].get('key_id') != state['target_key_id']:
                raise ValueError('既有回执的主密钥身份不符')
        if after['tenant'] != state['tenant'] or after['object_id'] != object_id:
            raise ValueError('轮换对象归属不符')
        if after['body'] != before['body'] or after['nonce'] != before['nonce']:
            raise ValueError('轮换改动了正文密文身份')
        if after['envelope']['context'] != context_for(state['tenant'], object_id, before['body']):
            raise ValueError('轮换包装上下文不符')
        # 先确认新信封确实解开同一正文，再提交检查点。
        if not hmac.compare_digest(
                read(self.store, self.service, after, state['tenant'], object_id),
                read(self.store, self.service, before, state['tenant'], object_id)):
            raise ValueError('轮换前后正文不一致')
        item['entry'] = after
        item['verified'] = True
        self._save(state)
        return after

    def resume(self, object_ids=None):
        """续作所有未核验对象；可选限制到给定对象集。"""
        state = self._load()
        if state is None:
            raise ValueError('没有可续作的轮换检查点')
        if state.get('published'):
            return self.status()  # 已发布的重送是幂等的
        wanted = None if object_ids is None else set(object_ids)
        for item in state['items']:
            if wanted is not None and item['object_id'] not in wanted:
                continue
            if not item['verified']:
                self.step(item['object_id'])
        return self.status()

    def complete(self):
        """验证全部对象并发布新目录版本。

        只有全部条目都通过逐对象认证时才把 ``main`` 切到新版本；验证失败、
        目录在轮换期间被他人改写或目录比较更新失败时，``main`` 保持旧版本，
        检查点仍可续作。旧版本在切换前被自动保留。
        """
        state = self._load()
        if state is None:
            raise ValueError('没有可续作的轮换检查点')
        entries = [item['entry'] for item in state['items']]
        if not entries or any(not item['verified'] for item in state['items']):
            raise ValueError('轮换尚未完成，不能切换目录')
        payload = {
            'format': FORMAT,
            'name': self.name,
            'tenant': state['tenant'],
            'key_id': state['target_key_id'],
            'entries': entries,
            'identity': _content_identity(entries),
        }
        digest = self.store.put_json(payload)
        # 发布前从对象仓重新读回，逐对象认证并核对租户/摘要/上下文。
        manifest = self._manifest(digest)
        if manifest['identity'] != _content_identity(entries):
            raise ValueError('新目录版本内容摘要不符')
        for entry in manifest['entries']:
            read(self.store, self.service, entry, state['tenant'], entry['object_id'])
        refs = self.catalog.read()
        if refs.get(self.name) == digest:
            # 上次切换已成功但检查点未落盘；补写发布状态即可，不重复切换。
            state['published'] = digest
            self._prune(state)
            self._save(state)
            return digest
        if refs.get(self.name) != state['base']:
            raise ValueError('目录在轮换期间已改变，保留检查点')
        # 旧版本与切换在同一把锁内完成：先登记保留引用，再切当前头，中间
        # 不会出现任何读者既没有旧路径也没有新目录的窗口。
        retain_ref = 'retained:%s:%s' % (self.name, state['base'])
        if retain_ref in refs and refs[retain_ref] != state['base']:
            raise ValueError('旧版本保留引用已被改写')
        self.catalog.compare_update_many(
            {self.name: state['base'],
             retain_ref: state['base'] if retain_ref in refs else None},
            {self.name: digest, retain_ref: state['base']},
        )
        state['published'] = digest
        self._prune(state)
        self._save(state)
        return digest

    @staticmethod
    def _prune(state):
        """完成发布后检查点只保留已核验包，避免旧信封继续被误用/审计。"""
        for item in state['items']:
            item.pop('original', None)

    # ------------------------------------------------------------ 退休审计
    def _pending_journals(self, key_id):
        """扫描同一目录根下所有检查点，返回仍持有该主密钥包装的对象。"""
        pending = {}
        for path in sorted(self.root.glob('rotation-*.json')):
            try:
                state = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                raise ValueError('轮换检查点无法读取：%s' % path.name)
            if state.get('format') != FORMAT:
                raise ValueError('轮换检查点格式不支持：%s' % path.name)
            if state.get('published'):
                continue
            for item in state.get('items', []):
                for entry in (item.get('original'), item.get('entry')):
                    if entry is not None and entry['envelope'].get('key_id') == key_id:
                        pending.setdefault(state.get('name'), []).append(item['object_id'])
                        break
        return {name: sorted(set(ids)) for name, ids in pending.items()}

    def _audit_locked(self, key_id):
        """在目录锁内审计所有实际引用，而不只是当前头。

        覆盖共享目录根下全部引用名（各命名字录的当前头、保留版本和钉住
        快照），并计入尚未发布的检查点；一个主密钥可能被多个租户目录同时
        使用，也可能只残留在未完成轮换的旧包装里。任何无法解释的目录引用
        都会显式报告，绝不被静默当作“没人用”。
        """
        refs = self.catalog.read()
        usage = {}
        unresolved = []
        for ref, digest in sorted(refs.items()):
            try:
                manifest = self.store.json(digest)
                _check_manifest(manifest)
            except (ValueError, OSError, TypeError):
                unresolved.append(ref)
                continue
            for entry in manifest['entries']:
                if entry['envelope'].get('key_id') == key_id:
                    slot = usage.setdefault(digest, {'refs': [], 'objects': []})
                    if ref not in slot['refs']:
                        slot['refs'].append(ref)
                    slot['objects'].append(entry['object_id'])
        pending = self._pending_journals(key_id)
        return {'key_id': key_id, 'references': usage,
                'unresolved_references': unresolved,
                'pending_rotation': pending,
                'referenced': bool(usage) or bool(unresolved),
                'pending': bool(pending)}

    def audit(self, key_id):
        """列出所有目录引用（含当前头、保留版本、快照保留）对该主密钥的使用。"""
        with self.catalog.locked():
            return self._audit_locked(key_id)

    def retire(self, key_id, operation):
        """在目录引用清空且服务给出回执后退休主密钥。

        判断依据是目录中所有实际引用和密钥服务回执，不是当前头。即使引用已
        清空，也只声明本地服务停用；不声称备份或快照副本已被物理销毁。
        """
        with self.catalog.locked():
            audit = self._audit_locked(key_id)
            if audit['unresolved_references']:
                raise ValueError('存在无法解释的目录引用：%s'
                                 % ','.join(audit['unresolved_references']))
            if audit['referenced'] or audit['pending']:
                raise ValueError('主密钥仍被目录引用或未完成轮换引用')
            receipt = self.service.retire(key_id, operation)
            if not isinstance(receipt, dict) or receipt.get('key_id') != key_id \
                    or receipt.get('status') != 'disabled':
                raise ValueError('密钥服务未给出有效停用回执')
            history = self._load_retirements()
            history[key_id] = {
                'receipt': receipt,
                'operation': operation,
                'audit': {'references': audit['references'],
                          'unresolved_references': audit['unresolved_references'],
                          'pending_rotation': audit['pending_rotation']},
                'physical_deletion': False,
                'note': RETIREMENT_NOTE,
            }
            _atomic_write(self.retirements, json.dumps(
                history, ensure_ascii=False, sort_keys=True, separators=(',', ':')
            ).encode('utf-8'))
        return history[key_id]

    def _load_retirements(self):
        if not self.retirements.exists():
            return {}
        return json.loads(self.retirements.read_text(encoding='utf-8'))

    def retirement(self, key_id):
        return self._load_retirements().get(key_id)


KeyRotation = Rotation
