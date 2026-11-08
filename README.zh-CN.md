# 无需 Packet Tracer，即可构建 Packet Tracer 实验

> **完全离线创建 Cisco Packet Tracer `.pkt` 实验与带评分的 `.pka` 活动，无需安装 Packet Tracer。**
> 本项目逆向分析了 Packet Tracer 的文件格式（两个容器家族，PT 4.1 至 9.0.1），
> 提供逐字节精确的编解码器，以及一个生成器——可直接写出设备、模块、连线、
> IOS 配置、PC IP、实验说明、活动向导密码与评分树，产出 Packet Tracer 能直接打开的文件。

<img src="https://raw.githubusercontent.com/aacanadaa/large-scale-packet-tracer/main/docs/iruma/img/pt_full_topology.png" alt="一个 392 设备的 Packet Tracer 企业级模型，完全由代码生成，在 Packet Tracer 9.0.1 中打开" width="100%">

*由代码生成，在 Packet Tracer 9.0.1 中打开。图中的
[**IRUMA-AB** 与 **Y-AMLT** 企业级模型](https://github.com/aacanadaa/large-scale-packet-tracer)
分别是 **386 与 392 台设备、752 条链路、28,073 行配置**，十二层纵深，
含 ASA 防火墙、WLC、IP 电话与工业/IoT 设备群。没有一样是手工绘制的。*

[![PyPI](https://img.shields.io/pypi/v/packet-tracer-pkt-format.svg)](https://pypi.org/project/packet-tracer-pkt-format/)
[![Docs](https://img.shields.io/badge/docs-aacanadaa.github.io-4c1.svg)](https://aacanadaa.github.io/packet-tracer-pkt-format/)
[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-ff5e5b?logo=kofi&logoColor=white)](https://ko-fi.com/suoim)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![No Packet Tracer needed](https://img.shields.io/badge/Packet_Tracer-not_required-32d74b.svg)](#无需-packet-tracer创建-packet-tracer)
[![Cisco Packet Tracer](https://img.shields.io/badge/Cisco_Packet_Tracer-1BA0D7?style=flat&logo=cisco&logoColor=white)](#状态--范围)

**Languages:** [English](README.md) | 简体中文

<p align="center">
  <img src="https://count.getloli.com/@aacanadaa-pkt-format?name=aacanadaa-pkt-format&theme=moebooru&padding=8&offset=0&align=top&scale=1.3&pixelated=1&darkmode=auto" alt="Visitors"/>
</p>

## 安装

```console
$ pip install packet-tracer-pkt-format
```

需要 Python 3.10 或更高版本。唯一的运行时依赖是 `pydantic`。读取、检视、对比、
导出与重新写回文件都不需要任何其他东西：不需要 Packet Tracer、不需要编译器、
不需要系统加密库。若系统存在 `libgcrypt`，以及可选的 Rust 扩展，会被自动作为
加速器启用；纯 Python 密码实现始终可用，作为参考路径。

## 快速上手

指向任意一个你手上已有的 `.pkt` 或 `.pka`：

```console
$ pkt info my_lab.pkt                          # 容器元数据、大小、根标签
$ pkt export my_lab.pkt --format graphviz -o topology.dot
$ pkt unpack my_lab.pkt -o out/                # XML + 每台设备的 IOS 配置 + 拓扑
$ pkt pack out/my_lab.xml -o rebuilt.pkt       # 逐字节重建
```

```python
from pkt_core import decode
from pkt_core.models import Lab

lab = Lab.from_bytes(decode("my_lab.pkt").xml)
print(len(lab.devices), "devices,", len(lab.links), "links")
for dev in lab.devices:
    print(dev.name, dev.kind, dev.model)
```

## 无需 Packet Tracer，创建 Packet Tracer

Packet Tracer 只在**打开**结果时才需要——实验本身是在这里编写的。
`Lab` 构建器随包一同发布，模板也一并打包，因此一次普通的 `pip install`
之后即可使用，无需检出仓库：

```python
from pkt_core import Lab

lab = Lab()                       # 内置种子文档与 137 台设备的模板库
lab.prune_seed_devices()          # 从空白画布开始
r  = lab.add_device("2911", "R1", 250, 350, install="HWIC-2T",
                    ios_config=["interface GigabitEthernet0/0",
                                " ip address 192.168.1.1 255.255.255.0", " no shutdown", "end"])
sw = lab.add_device("2960-24TT", "SW1", 450, 350)
pc = lab.add_device("PC-PT", "PC1", 650, 350,
                    pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"))
lab.link(r, "GigabitEthernet0/0", sw, "GigabitEthernet0/1")
lab.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
lab.save("my_lab.pkt")            # 在 Packet Tracer 中打开——上面的过程并未使用它
```

……或者从拓扑规格一步生成带评分、带密码的活动。
这些生成器位于 [`tools/`](tools)，需要从检出的仓库运行：

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

* 密码算法：**Twofish 的 EAX（AEAD）模式**，128 位密钥 = `0x89` 重复，IV = `0x10` 重复，
  末尾附加 16 字节标签。
* 加密前的包装：字节反转 + 位置相关 XOR。
* 解密后的包装：每个字节与 `(len - i)` 异或。
* 载荷：UTF-8 XML 文档的 Qt `qCompress`（zlib）。

现代家族的完整细节、证据与各格式密钥表见 **[FORMAT.md](FORMAT.md)**；
两个家族（含旧版容器）的完整规范见
**[FORMAT_SPECIFICATION.md](docs/FORMAT_SPECIFICATION.md)**。

## `pkt_core` 库

`pt9.py` 是自包含的参考编解码器；`src/pkt_core/` 是面向嵌入使用的**类型安全库**
（Python 3.10+）。CLI 只是它的薄封装，绝不会被反向导入。除 `pkt_core.builder` 外，
全部代码都在 `mypy --strict` 下检查完毕——`builder` 是编写层代码的移植，内部尚未
完整标注类型，但其公开签名已标注类型。

```python
from pkt_core import decode, encode_bytes

container = decode("lab.pkt")          # 格式由 AEAD 标签判定，
                                       # 而非魔数前缀；后者并不存在
print(container.root_tag)              # 'PACKETTRACER5'
print(container.is_activity)           # False  (.pka -> PACKETTRACER5_ACTIVITY)
xml = container.xml                    # 内层 XML 文档

rebuilt = encode_bytes(xml, container.format_name)
```

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
| `pkt_core.crypto.keys` | 各格式密钥表（`twofish`/`serpent128`/`cast256`，密钥与 IV 字节） |
| `pkt_core.crypto.stream` | 两层位置 XOR 混淆 |
| `pkt_core.crypto.ciphers_pure` | 纯 Python 的 Twofish / Serpent / CAST-256 |
| `pkt_core.codec.qcompress` | Qt `qCompress` 封装帧 |
| `pkt_core.codec.container` | 整个容器的检测 / 解码 / 编码 |
| `pkt_core.xml` | 无损字节级 XML 层（惰性解析、容忍 HTML） |
| `pkt_core.models` | 类型化视图：`Lab`、`Device`、`Port`、`Link`、`Cluster`、`RunningConfig` |
| `pkt_core.builder` | 编写层：`Lab`（放置、供电、模块、连线、配置）、`Layout` |
| `pkt_core.resources` | 内置设备模板库与种子文档 |
| `pkt_core.diff` | 语义级设备 / 链路 / 配置对比 |
| `pkt_core.export` | `graphviz`、`netbox`、`containerlab` 拓扑导出 |
| `pkt_core.errors` | 类型化异常，绝不抛裸 `Exception` |

模型是**无损 XML 树之上的视图**，而非并行数据结构：写出文档时，未改动的部分按原始
字节输出，因此数据丢失在结构上不可能发生。未识别的元素会进入各模型的 `extra_fields`，
而不是被丢弃。IOS `<LINE>` 配置暴露为 `bytes` 是有意为之——其中包含原始 `^C`
banner 定界符，解码会把它们规整掉。

AEAD 是**确定性**的：密钥与 IV 按格式固定，因此密钥流与文件无关，相同的 XML 永远
产生相同的字节。这也正是 EAX 标签能当作格式判别器（误报率 2⁻¹²⁸）而非魔数的原因。

本项目自产的样例容器提交在 [`corpus/samples/`](corpus/samples/) 下，测试开箱即用。
用于逆向分析的 1,026 个第三方文件**不**随仓库提交，分发策略见
[`corpus/README.md`](corpus/README.md)，重建方法见
[`corpus/fetch_corpus.py`](corpus/fetch_corpus.py)。

## 三种加密后端

| 后端 | Twofish | Serpent | CAST-256 |
| --- | --- | --- | --- |
| **Rust**（可选加速器） | 0.090 µs/块 | 0.151 µs | 0.209 µs |
| libgcrypt | 0.827 µs | 0.885 µs | 不支持 |
| 纯 Python（便携回退） | 13.2 µs | 47.6 µs | 18.7 µs |

Rust 比 libgcrypt 快约 9 倍，比纯 Python 快 90–315 倍。三种后端通过同一套已发布
测试向量（Twofish AES 提交向量、Serpent NESSIE 向量、CAST-256 RFC 2612 附录 A）
交叉验证，且互相逐字节一致。

## 用法

`pt9.py` 是最初的单文件读写器，无需安装；`pkt` 是完整的 CLI。`pkt` 不依赖
`libgcrypt`，只有需要加速密码路径时才装它（`apt install libgcrypt20`）。
`pt9.py` 则依赖它，因为它直接绑定 libgcrypt 来实现分组密码；在没有该库的机器上
请改用 `pkt` 或 `pkt_core` 包，它们自带纯 Python 的密码实现。

```console
$ python3 pt9.py info   my_lab.pkt
root tag  : PACKETTRACER5
xml bytes : 1045755

$ python3 pt9.py decode my_lab.pkt -o my_lab.xml
$ python3 pt9.py decode course_activity.pka -o activity.xml      # .pka 使用同一容器
$ python3 pt9.py encode my_lab.xml -o my_lab.pkt                 # 写回文件
$ python3 -m unittest discover -s tests -v                       # 自检
```

`pkt` 入口额外提供检视、对比、导出与审计：

```console
$ pkt info    my_lab.pkt                 # 容器元数据、大小、根标签
$ pkt unpack  my_lab.pkt -o out/         # XML + 每台设备的 IOS 配置 + 拓扑
$ pkt pack    out/my_lab.xml -o rebuilt.pkt   # 逐字节重建
$ pkt diff    before.pkt after.pkt       # 结构性差异
$ pkt export  my_lab.pkt --format graphviz    # graphviz / netbox / containerlab
$ pkt audit   my_lab.pkt --templates tools/device_templates.json
```

### `pkt audit` 存在的理由

计数只有在被计数的对象**互不相同**时才有意义。本工具早期版本发布过一个 290 设备的
模型，其服务总数被模板残留物虚增：202 个「AAA 客户端」中只有 140 个是真实的不同条目
（其余 63 个是从某台采集来的设备模板复制到每台设备上的同一个幽灵地址 `192.168.10.1`），
259 个「DHCP 地址池」中只有 131 个不同。此前的校验器只断言*存在性*，因此在报出这两个
错误数字的同时，打印出了 `PASSED (0 warnings)`。

`pkt audit` 会为每个服务类别同时打印原始计数与去重后的计数，标记出那些来自采集模板
而非出自作者的记录，并在发现任何重复时**以非零码退出**。以下是该企业级模型在被清理
*之前*的真实输出：

```console
$ pkt audit JASDF_AEWC_JADGE.pkt --templates tools/device_templates.json
device_names: 290 raw, 290 distinct
config lines  : min=78 median=143 max=250 total=22,648 (143 IOS/ASA devices,
                by model); 22,896 <LINE> elements in 205 RUNNINGCONFIG blocks
services      : 496 DNS records (248 distinct x 2 servers)
  aaa_clients: 202 raw, 140 distinct, 62 duplicate instances
               (e.g. 192.168.10.1 x63), 63 template leftovers -> 139 authored
  dhcp_pools : 259 raw, 133 distinct, 126 duplicate instances
               (e.g. serverPool / 0.0.0.0 / 0.0.0.0 x65), 128 template leftovers
  aaa_users  :  65 raw,   3 distinct, 62 duplicate instances (e.g. user x63)
  ftp_accounts: 64 raw,   3 distinct, 61 duplicate instances (e.g. cisco x62)
  FAIL duplicate-dhcp-pool-name: pool name 'serverPool' is used by 128 pools
  FAIL duplicate-dhcp-pool-name: pool name 'IRUMA-VLAN10' is used by 2 pools
  ...
RESULT: FAILED (15 failures, 0 warnings)
```

注意配置行那一行：它**同时**打印两个数字，并各自说明统计方法（按型号筛选 IOS/ASA
设备，对比全部 205 个配置块中的原始 `<LINE>` 元素）。早先的文档只公布了一个数字、
没有给出方法，导致无法复现。此后数字变过一次，从 22,579/22,827 变成 22,648/22,896，
原因是一台设备原先带着采集模板的出厂默认配置、后来被正确配置了。这正是要打印方法的
意义所在：数字是可核对的，因此它的变化能看出缘由。

这条规则也是库如今处处遵循的：**如果校验器打印了一个计数，它就必须证明这些条目互不相同。**

解密后的根元素示例：

```
<PACKETTRACER5>
  <VERSION>9.0.1.0858</VERSION>
  <PIXMAPBANK>…</PIXMAPBANK>
  <DEVICES>…</DEVICES>
  <LINKS>…</LINKS>
  …
```

## 状态 / 范围

**两个容器家族都已完整解码，双向可用。**
`encode(decode(f)) == f` 在 **1058 / 1058** 个真实容器上**逐字节精确**，
详见 [`docs/CORPUS_VERIFICATION.md`](docs/CORPUS_VERIFICATION.md)。

| 家族 | 由何版本写入 | 变换 | 已验证文件 |
| --- | --- | --- | --- |
| **现代** | PT **5.3.3** → 9.0.1 | layer A → Crypto++ EAX（Twofish）→ layer B → qCompress | 865 |
| **旧版** | PT **4.1** → 5.3.2 | layer B → qCompress（*无 AEAD、无反转*） | 193 |

* AEAD 认证标签精确复现，并在加载时校验。
* 已在 **Packet Tracer 9.0.1.0858**（Linux x86-64）与 **PT 4.1 至 9.0.1** 跨度的
  1,058 个真实文件上验证。
* **两个家族都没有魔数头。** 检测是「验证器式」的：现代家族用 EAX 标签
  （误报率 2⁻¹²⁸），旧版用结构性 qCompress 探测。容器在一处精确切换：5.3.2 → 5.3.3。
* 文档**并非总是良构 XML**：`<LINE>` 配置文本含原始控制字节
  （Cisco `banner motd ^C…^C` 的定界符是字面量 `\x03`），PT 4.1 文档以 NUL 结尾。
  不要使用校验式解析器。
* 共三种根元素：`PACKETTRACER5`、`PACKETTRACER5_ACTIVITY` 与
  `PACKETTRACER_ACTIVITY`（PT 4.x）。根元素**不是**容器判别依据。
* `.pkt`/`.pka` 已完整支持。`.pta`/`.pkc`（Serpent）与内部 `sm`/`userapp`（CAST-256）
  两种形态已有规范描述，但需要带 Serpent/CAST-256 的密码后端
  （系统自带的 `libgcrypt` 两者都没有）。

## 如何发现的

对带完整符号表的 `PacketTracer` 二进制做静态分析，定位到
`CNetworkFile::openFile`、`Util::encrypt*/decrypt*` 家族、泛型模板
`Util::cipher/decipher<Cipher>`，以及 Crypto++ 的 `EAX_Base` /
`AuthenticatedDecryptionFilter`。随后在 `Xvfb` 下以 `gdb` 断点无头运行
Packet Tracer，捕获精确的密文与明文，从而以字节级的确定性钉死了 CTR 计数器
与两层混淆。

## 生成文件

由于编码是逐字节精确的，同一套编解码器也能**写出** `.pkt` 文件。
工具位于 [`tools/`](tools)，说明见 [`docs/SCENE_GRAPH.md`](docs/SCENE_GRAPH.md)：

### 企业级规模

[`large-scale-packet-tracer`](https://github.com/aacanadaa/large-scale-packet-tracer)
里有两个完全以此方式生成的完整网络，均已验证可在 Packet Tracer 9.0.1 中打开。
它们就是上文截图中出现的模型：

| 网络 | 设备 | 链路 | 配置行 | 大小 |
| --- | ---: | ---: | ---: | ---: |
| Y-AMLT（横滨海运码头） | 386 | 380 | 15,345 | 1.33 MB |
| IRUMA-AB（日本航空自卫队空军基地） | 392 | 372 | 13,728 | 1.40 MB |

每个网络都附带三套剖档（enterprise / standard / smoke），以便不必每次打开 392 设备
的画布就能迭代。那个仓库也是后来成为 [`SKILL.md`](SKILL.md) 各条规则的大型拓扑
经验被摸索出来的地方。

一个可运行的六设备完整流程（构建、打开、OSPF 收敛、跨两台路由器 ping）见
[`demo/build_demo.py`](demo/build_demo.py)：`pip install packet-tracer-pkt-format`，
运行它，再打开它写出的文件即可。参考材料（格式规范、schema、场景图、验证报告）
放在[文档站](https://aacanadaa.github.io/packet-tracer-pkt-format/)，以便本文件
保持为一份参考。

* `tools/harvest_merge.py`：从一批既有 `.pkt` 文件中采集每种型号的一台完整设备，
  合并到同一张画布上，并处理 PT 所需的物理工作区重映射。
* `tools/build_wired_lab.py`：同上，**外加自动连线**：把每台具备以太网能力的设备
  接到由核心交换机组成的骨干上，并把核心交换机串联起来。
* `tools/build_configured_lab.py`：一个**可工作、已配置**的完整实验
  （`PC1－SW1－R1＝R2－SW2－PC2`，含 IP、网关、静态路由，以及可选的
  长运行配置）。IOS 配置以 `<RUNNINGCONFIG><LINE>…` 命令写入，加载时生效；
  PC 获得 `<IP>/<SUBNET>/<PORT_GATEWAY>`。见
  [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)。
* `tools/activity.py` + `tools/scoring.py`：用 Activity Wizard 编写**活动文件
  （`.pka`）**：说明（HTML）、**活动向导密码**、权限、反馈、**初始 / 答案网络**，
  以及**评分树**。见 [`docs/ACTIVITY.md`](docs/ACTIVITY.md)。
* `tools/make_scored_lab.py`：**一次性离线生成器**：从拓扑规格（`--spec`）出发，
  构建初始与答案网络、推导评分，写出带评分的 `.pka`。无需 Packet Tracer。
  自带 **137 个设备模板、78 个模块模板与 14 种评分形态**
  （`tools/device_templates.json`、`tools/device_shapes.json`）。
* `tools/harvest_library.py`：从你自己的 `.pkt`/`.pka` 文件（重新）构建上述库，
  以扩展型号/形态覆盖范围。
* `tools/lab_api.py`：一组**已验证的编写操作**的小型库
  （放置设备、开/关电源、安装模块、连接铜缆、写入 IOS `RUNNINGCONFIG`、
  设置 PC IP/DHCP）。能力矩阵与细节见
  [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md)。
* 编辑：解码 → 修改设备名/配置/位置 → 编码 → PT 即可打开。

在此运行有线构建器的结果：**147 台设备、140 个不同型号、71 条电缆**
（路由器、交换机、ASA、WLC、AP、IP 电话、PC/笔记本/平板、服务器，以及一大套
IoT/工业设备）在同一个文件中，Packet Tracer 能打开并正确绘制连线。

给所有要生成文件的人的关键事实（细节见场景图笔记）：

* 设备带有一份*物理场景*摆放数据，合并时必须重映射。
* 电缆通过 `<FROM>`/`<TO>` 的 id 与 `<PORT>` 名称绑定；设备需要
  `<ENGINE>/<SAVE_REF_ID>`，且端口必须存在于那个确切的实例上。
  `*_MEM_ADDR` 字段不做校验；PT 会自行重绑。

## 语料库

逆向分析基于 **1,026 个不重复的真实容器**，来自 40 个公开上游。
二进制文件**不**随仓库分发（版权原因），但身份信息在：

* [`corpus/CORPUS_INDEX.tsv`](corpus/CORPUS_INDEX.tsv) — 权威清单：文件名、大小、SHA-256
* [`corpus/fetch_corpus.py`](corpus/fetch_corpus.py) — 从上游重建逐字节相同的本地副本
* [`corpus/samples/`](corpus/samples/) — 本项目自产、GPL 授权的样例，测试开箱即用

## 法律 / 伦理

* 面向**互操作性**研究：使用本地合法授权的 Packet Tracer 副本，以及作者自己的文件。
* 不绕过任何 DRM 或授权保护；此处不存在加密密码。
* 用于读取*你自己的*文件、格式文档、工具链与归档。
* **不要**用它获取、篡改或提交评测/竞赛的答案。那是作弊，不在本项目范围内。

## 许可证

**GNU General Public License v3.0 或更高版本** — 见 [LICENSE](LICENSE)。

你可以依据该许可证使用、修改和再分发本软件，**包括商业用途**。GPL 本身已允许
商业使用，不存在需要另行洽谈的商业授权。

本项目早期版本曾以非商业许可证分发，但那只适用于当时的版本；自添加 GPL 的那个
提交起，GPL 是唯一适用的许可证。

## 参考文档

| 文档 | 内容 |
| --- | --- |
| [FORMAT_SPECIFICATION.md](docs/FORMAT_SPECIFICATION.md) | 两种容器家族的完整二进制格式规范 |
| [SCHEMA_REFERENCE.md](docs/SCHEMA_REFERENCE.md) | 全部 1,285 个 XML 元素名的参考 |
| [LEGACY_FORMAT.md](docs/LEGACY_FORMAT.md) | PT 5.x 旧版容器的逆向过程与假设阶梯 |
| [CORPUS_VERIFICATION.md](docs/CORPUS_VERIFICATION.md) | 1058/1058 逐字节验证 |
| [PKA_GENERATION.md](docs/PKA_GENERATION.md) | 仅用本仓库生成完整评分 `.pka` |
| [LARGE_TOPOLOGY_TEST.md](docs/LARGE_TOPOLOGY_TEST.md) | 77 设备大型拓扑的生成与实测 |
| [PACKET_TRACER_VALIDATION.md](docs/PACKET_TRACER_VALIDATION.md) | 在真实 Packet Tracer 中的验证 |

## Star history

<a href="https://www.star-history.com/?repos=aacanadaa%2Fpacket-tracer-pkt-format&type=date&legend=top-left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=aacanadaa/packet-tracer-pkt-format&type=date&theme=dark&legend=top-left" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=aacanadaa/packet-tracer-pkt-format&type=date&legend=top-left" />
    <img alt="Star history chart" src="https://api.star-history.com/chart?repos=aacanadaa/packet-tracer-pkt-format&type=date&legend=top-left" />
  </picture>
</a>

---

如果本项目对你有帮助，可以请我喝杯咖啡：

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20me-ff5e5b?logo=kofi&logoColor=white)](https://ko-fi.com/suoim)
