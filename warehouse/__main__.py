"""资料读取与密钥轮换管理入口。"""
import argparse, json, os, tempfile
from pathlib import Path
from .objects import ObjectStore
from .envelope import inspect, seal
from .key_service import KeyService, load_runtime_masters
from .catalog import Catalog
from .rotation import Rotation


def _source(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _open(root, source):
    """打开运行目录，并按需用合成资料建立初始目录版本（幂等）。"""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    store = ObjectStore(root/'objects')
    # 主密钥只驻留服务实例与未跟踪运行目录，绝不进入目录版本或检查点。
    service = KeyService(load_runtime_masters(root, source['keys']))
    catalog = Catalog(root/'catalog')
    if not catalog.read().get('main'):
        by_tenant = {}
        for obj in source['objects']:
            e = seal(store, service, obj['tenant'], obj['object_id'],
                     obj['content'].encode(), source['keys'][0], obj['object_id'])
            by_tenant.setdefault(obj['tenant'], []).append(
                {'tenant': e['tenant'], 'object_id': e['object_id'], 'body': e['body'],
                 'nonce': e['nonce'], 'envelope': e['envelope']})
        for index, (tenant, group) in enumerate(by_tenant.items()):
            name = 'main' if index == 0 else 'main:%s' % tenant
            Rotation(store, service, catalog, name).publish(tenant, group, source['keys'][0])
    return store, service, catalog


def _dump(value):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description='读取、核对本地资料或管理密钥轮换')
    parser.add_argument('--source', default='data/source.json')
    sub = parser.add_subparsers(dest='command')
    read = sub.add_parser('read', help='读取并核对资料（不写入运行目录）')
    read.add_argument('--source', default=argparse.SUPPRESS)

    rotate = sub.add_parser('rotate', help='可续作地重新包装文件密钥')
    rotate.add_argument('--source', default=argparse.SUPPRESS)
    rotate.add_argument('--root', default='.runtime')
    rotate.add_argument('--name', default='main', help='目录引用名，默认 main')
    rotate.add_argument('--tenant')
    rotate.add_argument('--key', dest='key_id')
    rotate.add_argument('--resume', action='store_true', help='续作未完成的轮换')
    rotate.add_argument('--complete', action='store_true', help='验证并切换目录版本')

    audit = sub.add_parser('audit', help='审计目录引用中的主密钥使用')
    audit.add_argument('--source', default=argparse.SUPPRESS)
    audit.add_argument('--root', default='.runtime')
    audit.add_argument('--name', default='main')
    audit.add_argument('--tenant')
    audit.add_argument('--key', dest='key_id', required=True)

    parser.set_defaults(command='read')
    args = parser.parse_args()
    source = _source(args.source)

    if args.command == 'read':
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); store = ObjectStore(root/'objects')
            _dump(inspect(source, store, root))
        return

    store, service, catalog = _open(args.root, source)
    rotation = Rotation(store, service, catalog, args.name)
    if args.command == 'audit':
        _dump(rotation.audit(args.key_id))
        return

    tenant = args.tenant
    if args.resume:
        if rotation.status() and rotation.status().get('published'):
            _dump(rotation.status())
        else:
            _dump(rotation.resume())
        return
    if args.complete:
        _dump({'published': rotation.complete()})
        return
    if not tenant or not args.key_id:
        parser.error('开始轮换需要 --tenant 和 --key')
    if not rotation.status() or rotation.status().get('published'):
        rotation.begin(tenant, args.key_id)
    if rotation.status().get('published'):
        _dump(rotation.status())
    else:
        _dump(rotation.resume())


if __name__ == '__main__':
    main()
