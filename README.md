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
