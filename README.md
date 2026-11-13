# 湖表加密对象资料工具

Python 3.11 项目，用于读取、保存及核对协作资料仓的本地资料。不可变内容通过 SHA256 寻址，目录引用单独保存。现有领域接口位于 warehouse/envelope.py，资料契约见 docs/contracts.md，合成输入位于 data/source.json。warehouse/objects.py 负责内容校验，catalog.py 负责本地引用更新，snapshot.py 提供完整行快照基础读取。

已有读取流程使用临时目录，不改变源资料。当前只提供源码中已实现的基础操作，输出相应对象身份、行或引用摘要。领域接口的测试说明其现有边界，不承诺额外的管理或查询功能。

运行与开发检查：

```sh
python -m unittest discover -s tests -v
python -m compileall -q warehouse tests
python -m warehouse
```

认证加密使用 cryptography，依赖已在项目镜像中准备：

```sh
python -m pip install -r requirements.txt
```

密钥由运行实例生成，只驻留于服务对象；公开资料不包含有效主密钥。

可续作的密钥轮换与版本管理在 warehouse/rotation.py，契约细节见 docs/contracts.md：

```sh
python -m warehouse rotate --tenant alpha --key master-2   # 开始或恢复，逐对象重包装
python -m warehouse rotate --resume                        # 故障/中断后继续
python -m warehouse rotate --complete                      # 全量核验后切换目录版本
python -m warehouse audit --key master-1                   # 查看目录引用中的主密钥使用
```

轮换期间读者继续读旧目录；未核验完整不会切换。退休只在所有目录引用（当前头、
保留版本、钉住快照、未完成检查点）都不再使用该主密钥且服务返回回执后进行，
回执明确不代表备份或快照副本已物理销毁。
