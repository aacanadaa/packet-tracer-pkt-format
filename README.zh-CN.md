# 无需 Packet Tracer，即可构建 Packet Tracer 实验

> **完全离线创建 Cisco Packet Tracer `.pkt` 实验与带评分的 `.pka` 活动，无需安装 Packet Tracer。**
> 本项目逆向分析了 Packet Tracer 9 的文件格式，提供逐字节精确的编解码器，
> 以及一个生成器——可直接写出设备、模块、连线、IOS 配置、PC IP、实验说明、
> 活动向导密码与评分树，产出 Packet Tracer 能直接打开的文件。

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![No Packet Tracer needed](https://img.shields.io/badge/Packet_Tracer-not_required-32d74b.svg)](#快速上手)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-ff5e5b?logo=kofi&logoColor=white)](https://ko-fi.com/suoim)

**Languages:** [English](README.md) | 简体中文

## 无需 Packet Tracer，创建 Packet Tracer

Packet Tracer 只在**打开**结果时才需要——实验本身是在这里编写的：

```python
import lab_api
models, modules = lab_api.load_templates("tools/device_templates.json")
lab = lab_api.Lab("tools/network_seed.xml", models, modules)
r  = lab.add_device("2911", "R1", 250, 350, install="HWIC-2T",
                    ios_config=["interface GigabitEthernet0/0",
                                " ip address 192.168.1.1 255.255.255.0", " no shutdown", "end"])
sw = lab.add_device("2960-24TT", "SW1", 450, 350)
pc = lab.add_device("PC-PT", "PC1", 650, 350,
                    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"))
lab.link(r, "GigabitEthernet0/0", sw, "GigabitEthernet0/1")
lab.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
lab.save("my_lab.pkt")            # 在 Packet Tracer 中打开——构建过程未使用它
```

或者从拓扑规格一步生成带评分、带密码的活动：

```console
$ python3 tools/make_scored_lab.py --out mylab.pka --spec topology.json --password hunter2
```

---

现代 Packet Tracer 文件**没有魔数头**，且完全加密，因此 `file`、`strings` 与十六进制
查看器只能看到噪声。本项目记录了该容器格式，并提供一个小型读取器，可将 `.pkt`/`.pka`
还原为 Packet Tracer 内部存储的纯 XML。

## 速览

```
.pkt  ..  [ scramble ] -> [ Twofish-EAX, key=0x89*16, iv=0x10*16 ] ->
          [ XOR (len-i) ] -> [ qCompress/zlib ] -> "<?xml ... <PACKETTRACER5>"
```

* 密码算法：**Twofish 的 EAX（AEAD）模式**，128 位密钥 = `0x89` 重复，IV = `0x10` 重复，末尾附加 16 字节标签。
* 加密前的包装：字节反转 + 位置相关 XOR。
* 解密后的包装：每个字节与 `(len - i)` 异或。
* 载荷：UTF-8 XML 文档的 Qt `qCompress`（zlib）。

**另有 PT 5.x（4.1 – 5.3.2）的旧版容器**：没有 AEAD，也没有字节反转，
只是 `layer_b` 作用在 qCompress 载荷上。容器在 **5.3.2 → 5.3.3** 之间切换。

完整细节、证据与各格式密钥表见 **[docs/FORMAT_SPECIFICATION.md](docs/FORMAT_SPECIFICATION.md)**。

## 两种容器家族

| 家族 | 由何版本写入 | 变换 | 已验证文件 |
| --- | --- | --- | --- |
| **现代** | PT **5.3.3** → 9.0.1 | layer A → Crypto++ EAX（Twofish）→ layer B → qCompress | 865 |
| **旧版** | PT **4.1** → 5.3.2 | layer B → qCompress（*无 AEAD、无反转*） | 193 |

`encode(decode(f)) == f` 在 **1058 / 1058** 个真实容器上**逐字节精确**。
详见 [docs/CORPUS_VERIFICATION.md](docs/CORPUS_VERIFICATION.md)。

## `pkt_core` 库

`pt9.py` 是自包含的参考编解码器；`src/pkt_core/` 是面向嵌入使用的**类型安全库**
（`mypy --strict`，Python 3.10+）——CLI 只是它的薄封装，绝不会被反向导入。

```python
from pkt_core import decode
from pkt_core.models import Lab

lab = Lab.from_bytes(decode("lab.pkt").xml)
for dev in lab.devices:
    print(dev.name, dev.kind, dev.model, dev.position)
for link in lab.links:
    print(link.port_names, link.cable_type)
```

| 模块 | 职责 |
| --- | --- |
| `pkt_core.crypto.primitives` | CMAC（RFC 4493）、大端 CTR、Crypto++ EAX 变体 |
| `pkt_core.crypto.keys` | 各格式密钥表 |
| `pkt_core.crypto.stream` | 两层位置 XOR 混淆 |
| `pkt_core.crypto.ciphers_pure` | 纯 Python 的 Twofish / Serpent / CAST-256 |
| `pkt_core.codec.container` | 整个容器的检测 / 解码 / 编码 |
| `pkt_core.xml` | 无损字节级 XML 层（惰性解析、容忍 HTML） |
| `pkt_core.models` | 类型化视图：`Lab`、`Device`、`Port`、`Link`、`Cluster`、`RunningConfig` |
| `pkt_core.diff` | 语义级设备 / 链路 / 配置对比 |
| `pkt_core.export` | `graphviz`、`netbox`、`containerlab` 拓扑导出 |

模型是**无损 XML 树之上的视图**，而非并行数据结构：写出文档时，未改动的部分按原始
字节输出，因此数据丢失在结构上不可能发生。未识别的元素会进入各模型的 `extra_fields`，
而不是被丢弃。IOS `<LINE>` 配置暴露为 `bytes` 是有意为之——其中包含原始 `^C`
banner 定界符，解码会把它们规整掉。

## 快速上手

```console
$ pip install -e .                       # 或从源码运行
$ pkt info   my_lab.pkt
$ pkt unpack my_lab.pkt -o out/         # XML + 设备配置 + 拓扑图
$ pkt pack   out/lab.xml -o my_lab.pkt
$ pkt diff   a.pkt b.pkt                # 语义级差异
$ pkt export my_lab.pkt --format graphviz
```

## 状态 / 范围

* **双向完全解码**，`encode(decode(f)) == f` 在 1058 个真实文件上逐字节精确。
* AEAD 标签精确复现，并在加载时校验。
* 在 **Packet Tracer 7.3.1 与 9.0.1** 中实测：重打包文件可打开并渲染，
  含一份经修改后重新编码的文件，以及一个完整评分的 `.pka` 活动。
* **两个家族都没有魔数头**，因此检测是"验证器式"的：EAX 标签作为现代家族的
  完整性判据（误报率 2⁻¹²⁸），旧版走结构性 qCompress 探测。
* 文档**并非总是良构 XML**：`<LINE>` 配置文本含原始控制字节
  （Cisco `banner motd ^C…^C` 的定界符是字面量 `0x03`），PT 4.1 文档以 NUL 结尾。
  不要使用校验式解析器。
* 三种根元素：`PACKETTRACER5`、`PACKETTRACER5_ACTIVITY`、`PACKETTRACER_ACTIVITY`（PT 4.x）。
  根元素**不是**容器判别依据。

## 三种加密后端

| 后端 | Twofish | Serpent | CAST-256 |
| --- | --- | --- | --- |
| **Rust**（可选加速器） | 0.090 µs/块 | 0.151 µs | 0.209 µs |
| libgcrypt | 0.827 µs | 0.885 µs | 不支持 |
| 纯 Python（便携回退） | 13.2 µs | 47.6 µs | 18.7 µs |

Rust 比 libgcrypt 快约 9 倍，比纯 Python 快 90–315 倍。三种后端通过同一套已发布
测试向量（Twofish AES 提交向量、Serpent NESSIE 向量、CAST-256 RFC 2612 附录 A）
交叉验证，且互相逐字节一致。

## 语料库

逆向分析基于 **1,026 个不重复的真实容器**，来自 40 个公开上游。
二进制文件**不**随仓库分发（版权原因），但身份信息在：

* [`corpus/CORPUS_INDEX.tsv`](corpus/CORPUS_INDEX.tsv) — 权威清单：文件名、大小、SHA-256
* [`corpus/fetch_corpus.py`](corpus/fetch_corpus.py) — 从上游重建逐字节相同的本地副本
* [`corpus/samples/`](corpus/samples/) — 本项目自产、GPL 授权的样例，测试开箱即用

## 文档

| 文档 | 内容 |
| --- | --- |
| [FORMAT_SPECIFICATION.md](docs/FORMAT_SPECIFICATION.md) | 两种容器家族的完整二进制格式规范 |
| [SCHEMA_REFERENCE.md](docs/SCHEMA_REFERENCE.md) | 全部 1,285 个 XML 元素名的参考 |
| [LEGACY_FORMAT.md](docs/LEGACY_FORMAT.md) | PT 5.x 旧版容器的逆向过程与假设阶梯 |
| [CORPUS_VERIFICATION.md](docs/CORPUS_VERIFICATION.md) | 1058/1058 逐字节验证 |
| [PKA_GENERATION.md](docs/PKA_GENERATION.md) | 仅用本仓库生成完整评分 `.pka` |
| [LARGE_TOPOLOGY_TEST.md](docs/LARGE_TOPOLOGY_TEST.md) | 77 设备大型拓扑的生成与实测 |
| [PACKET_TRACER_VALIDATION.md](docs/PACKET_TRACER_VALIDATION.md) | 在真实 Packet Tracer 中的验证 |

## 法律 / 伦理

* 面向**互操作性**研究：读取与重建你自己安装的 Packet Tracer 所产生的文件。
* 不包含任何 Cisco 版权素材；语料库通过清单 + 哈希 + 取回脚本记录，而非随仓库分发。
* 不要用于篡改评测或竞赛文件。

## 许可证

**GNU General Public License v3.0 或更高版本** — 见 [LICENSE](LICENSE)。

非商业用途免费。如需商业使用，请开 issue 联系商谈商业授权。


---

如果本项目对你有帮助，可以请我喝杯咖啡：

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-ff5e5b?logo=kofi&logoColor=white)](https://ko-fi.com/suoim)
