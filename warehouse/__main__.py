"""现有资料读取入口。"""
import json,tempfile,argparse
from pathlib import Path
from .objects import ObjectStore
from .envelope import inspect

def main():
    parser=argparse.ArgumentParser(description='读取并核对本地资料')
    parser.add_argument('--source',default='data/source.json');args=parser.parse_args()
    data=json.loads(Path(args.source).read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary);store=ObjectStore(root/'objects')
        result=inspect(data,store,root)
        print(json.dumps(result,ensure_ascii=False,sort_keys=True))
if __name__=='__main__':main()
