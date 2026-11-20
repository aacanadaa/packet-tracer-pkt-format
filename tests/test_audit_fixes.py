"""Regression tests for the 0.4.3 audit fixes (security, models, diff, export, builder, CLI)."""

from __future__ import annotations

import importlib.util
import json
import struct
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import pkt_core
from pkt_core import (
    CompressionError,
    FormatError,
    PacketTracerError,
    TruncatedFileError,
    __version__,
    decode_bytes,
    detect_format,
    encode_bytes,
    qcompress,
    quncompress,
    root_tag,
)
from pkt_core.audit import (
    TemplateLeftovers,
    _engine_views,
    format_identity,
    inventory,
    sanitize_engine,
    strip_service_records,
)
from pkt_core.builder import Lab as BuilderLab
from pkt_core.builder.lab import load_tier_map, tier_for_name
from pkt_core.cli.main import main as cli_main
from pkt_core.crypto import ciphers as ciphers_mod
from pkt_core.crypto.ciphers import CIPHER_KEY_SIZES, LibgcryptCipher, get_cipher
from pkt_core.crypto.primitives import EaxResult, ctr_crypt, eax_seal, eax_verify
from pkt_core.diff import diff_labs
from pkt_core.export import ExportError, to_containerlab, to_graphviz, to_netbox
from pkt_core.models import Lab, Port
from pkt_core.models.schema import CanvasShape, PortConfig, ScoringNode
from pkt_core.resources import load_device_templates
from pkt_core.xml import element, escape_xml_text, parse_xml_bytes


# --------------------------------------------------------------------------
# 1. Crypto, Native Leaks & Codec/XML
# --------------------------------------------------------------------------
def test_cast256_rfc2612_key_sizes() -> None:
    assert CIPHER_KEY_SIZES["cast256"] == (16, 20, 24, 28, 32)
    for size in (16, 20, 24, 28, 32):
        c = get_cipher("cast256", b"\x01" * size, backend="pure")
        assert c.key_size == size
        assert len(c.encrypt_block(b"\x00" * 16)) == 16


def test_disable_rust_env_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    for falsy in ("", "0", "false", "FALSE", "no", "off"):
        monkeypatch.setenv("PKT_CORE_DISABLE_RUST", falsy)
        assert ciphers_mod._rust_disabled_by_env() is False
    for truthy in ("1", "true", "yes"):
        monkeypatch.setenv("PKT_CORE_DISABLE_RUST", truthy)
        assert ciphers_mod._rust_disabled_by_env() is True


def test_libgcrypt_handle_close_and_setkey_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[object] = []

    class FakeLib:
        def has(self, name: str) -> bool:
            return name == "twofish"

        def open(self, name: str) -> object:
            return object()

        def setkey(self, handle: object, key: bytes) -> None:
            if key == b"\xff" * 16:
                raise pkt_core.UnsupportedCipherError("bad key")

        def close(self, handle: object) -> None:
            closed.append(handle)

        def encrypt(self, handle: object, block: bytes) -> bytes:
            return block

    monkeypatch.setattr(ciphers_mod, "_LIB_PROBED", True)
    monkeypatch.setattr(ciphers_mod, "_LIB", FakeLib())

    # setkey failure must close handle
    with pytest.raises(pkt_core.UnsupportedCipherError):
        LibgcryptCipher("twofish", b"\xff" * 16)
    assert len(closed) == 1

    # explicit close is idempotent and prevents further encryption
    c = LibgcryptCipher("twofish", b"\x00" * 16)
    assert c.encrypt_block(b"\x11" * 16) == b"\x11" * 16
    c.close()
    c.close()
    assert len(closed) == 2
    with pytest.raises(ValueError, match="closed"):
        c.encrypt_block(b"\x11" * 16)


def test_qcompress_bomb_protection_and_error_wrapping() -> None:
    # A 1 MiB zero payload compresses tiny, but declares only 10 bytes
    big = b"\x00" * (1024 * 1024)
    bomb = struct.pack(">I", 10) + zlib.compress(big)
    with pytest.raises(CompressionError):
        quncompress(bomb)

    # Truncated zlib stream
    good = qcompress(b"hello world" * 100)
    with pytest.raises(CompressionError):
        quncompress(good[:-6])

    # Invalid zlib level wrapped as CompressionError
    with pytest.raises(CompressionError):
        qcompress(b"abc", level=99)


def test_root_tag_skips_prologues_and_guards_empty() -> None:
    xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b"<!-- a comment with <FAKE> tag -->\n"
        b"<!DOCTYPE foo>\n"
        b"<PACKETTRACER5 attr='1'/>"
    )
    assert root_tag(xml) == "PACKETTRACER5"
    assert root_tag(b"<>") == "?"
    assert root_tag(b"</closing>") == "?"
    assert root_tag(b"<!-- unterminated") == "?"


def test_short_legacy_container_and_unknown_format_error() -> None:
    # A tiny 1-byte XML payload produces a legacy container < 16 bytes (>= 6 bytes)
    raw = encode_bytes(b"a", fmt="legacy")
    assert 6 <= len(raw) < 16
    assert detect_format(raw) == "legacy"
    c = decode_bytes(raw)
    assert c.format_name == "legacy"
    assert c.xml == b"a"

    with pytest.raises(FormatError):
        encode_bytes(b"<A/>", fmt="nonexistent")
    with pytest.raises(FormatError):
        decode_bytes(raw, fmt="nonexistent")


def test_primitives_ctr_nonce_bulk_and_cmac_only_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    key = b"\x89" * 16
    iv = b"\x10" * 16
    ct = eax_seal("twofish", key, iv, b"payload" * 20)

    # Validate nonce length
    cipher = get_cipher("twofish", key, backend="pure")
    with pytest.raises(ValueError, match="16 bytes"):
        ctr_crypt(cipher.encrypt_block, b"\x00" * 12, b"abc")

    # Bulk encrypt_blocks path produces identical output to per-block path
    calls: list[int] = []

    class BulkCipher:
        def encrypt_block(self, blk: bytes) -> bytes:
            return cipher.encrypt_block(blk)

        def encrypt_blocks(self, data: bytes) -> bytes:
            calls.append(len(data))
            return b"".join(
                cipher.encrypt_block(data[i : i + 16]) for i in range(0, len(data), 16)
            )

    nonce = b"\x42" * 16
    msg = b"hello world!" * 5
    assert ctr_crypt(BulkCipher().encrypt_block, nonce, msg) == ctr_crypt(
        cipher.encrypt_block, nonce, msg
    )
    assert calls == [64]

    # eax_verify must NOT call ctr_crypt
    def boom(*_a: object, **_k: object) -> bytes:
        raise AssertionError("ctr_crypt must not be called by eax_verify")

    monkeypatch.setattr("pkt_core.crypto.primitives.ctr_crypt", boom)
    assert eax_verify("twofish", key, iv, ct) is True
    assert eax_verify("twofish", key, iv, ct[:-1] + bytes([ct[-1] ^ 1])) is False
    with pytest.raises(TruncatedFileError):
        eax_verify("twofish", key, iv, b"\x00" * 4)

    res = EaxResult(b"", b"a" * 16, b"a" * 16)
    assert res.valid is True


def test_xml_escaping_depth_eof_and_dirty_writer() -> None:
    assert escape_xml_text('a & <b > c') == "a &amp; &lt;b &gt; c"

    el = element("TAG")
    assert el.dirty is True
    el.set("a", 'x&y < "z"')
    assert b'a="x&amp;y &lt; &quot;z&quot;"' in el.to_bytes()

    # Single-quoted attribute preserves quote and escapes apostrophe
    doc = parse_xml_bytes(b"<TAG a='old'/>")
    doc.root.set("a", "it's <good> & fine")
    assert b"a='it&apos;s &lt;good> &amp; fine'" in doc.to_bytes()

    # Trailing text on unterminated element at EOF
    unterminated = parse_xml_bytes(b"<ROOT>trailing text")
    assert unterminated.root.text == "trailing text"

    # Max nesting depth raises FormatError, not RecursionError
    deep = b"<A>" * 520 + b"</A>" * 520
    with pytest.raises(FormatError, match="depth"):
        _ = parse_xml_bytes(deep).root

    # Leading closing tag & empty tag names
    with pytest.raises(FormatError):
        parse_xml_bytes(b"</ROOT>")
    with pytest.raises(FormatError):
        parse_xml_bytes(b"<>")


# --------------------------------------------------------------------------
# 2. Models, Audit, Diff & Export
# --------------------------------------------------------------------------
def test_models_base_network_lab_schema_fixes() -> None:
    xml = (
        b"<PACKETTRACER5_ACTIVITY>"
        b"<PACKETTRACER5>"
        b"<OPTIONS><LANGUAGE>English</LANGUAGE></OPTIONS>"
        b"<CLUSTERS><ROOTCLUSTER><NAME>Root</NAME><CLUSTERID>1-1</CLUSTERID></ROOTCLUSTER></CLUSTERS>"
        b"<RECTANGLES><RECTANGLE><TopLeftX>0</TopLeftX><TopLeftY>0</TopLeftY>"
        b"<BottomRightX>100</BottomRightX><BottomRightY>50</BottomRightY><X>999</X></RECTANGLE></RECTANGLES>"
        b"<NETWORK><DEVICES>"
        b"<DEVICE><ENGINE><TYPE model='2960'>Switch</TYPE><NAME>S1</NAME>"
        b"<MODULE><PORT><TYPE>FastEthernet</TYPE><POWER>false</POWER></PORT>"
        b"<PORT><TYPE>FastEthernet</TYPE></PORT></MODULE></ENGINE>"
        b"<WORKSPACE><LOGICAL><DEV_ADDR>100</DEV_ADDR><MEM_ADDR>200</MEM_ADDR></LOGICAL></WORKSPACE></DEVICE>"
        b"<DEVICE><ENGINE><TYPE model='2960'>Switch</TYPE><NAME>S2</NAME></ENGINE></DEVICE>"
        b"</DEVICES><LINKS/></NETWORK>"
        b"</PACKETTRACER5>"
        b"</PACKETTRACER5_ACTIVITY>"
    )
    lab = Lab.from_bytes(xml)
    assert lab.options is not None and lab.options.language == "English"
    assert len(lab.clusters) == 1 and lab.clusters[0].name == "Root"
    # Direct children only (1 rectangle, not its <TopLeftX> etc. children)
    assert len(lab.canvas_shapes) == 1
    assert lab.canvas_shapes[0].bounds == (0.0, 0.0, 100.0, 50.0)

    d1, d2 = lab.devices
    assert d1 == lab.devices[0]
    assert d1 != d2
    assert d1.workspace is not None
    assert d1.workspace.dev_addr == "100"
    assert d1.workspace.mem_addr == "200"
    assert d1.ports[0].power is False
    assert d1.ports[1].power is True

    # Escaping in set_name and _set_text, plus OverflowError in _int
    d1.set_name("R&D <1>")
    assert b"R&amp;D &lt;1&gt;" in d1.to_xml()
    d1._set_text("INFVAL", "inf")
    assert d1._int("INFVAL", default=42) == 42

    # ScoringNode.children: multiple COMPONENTS, no duplicated grandchildren
    sn_xml = (
        b"<NODE><ID>root</ID>"
        b"<COMPONENTS><NODE><ID>c1</ID><NODE><ID>gc1</ID></NODE></NODE></COMPONENTS>"
        b"<COMPONENTS><NODE><ID>c2</ID></NODE></COMPONENTS>"
        b"<NODE><ID>d1</ID><NODE><ID>gc2</ID></NODE></NODE>"
        b"</NODE>"
    )
    sn = ScoringNode.from_element(parse_xml_bytes(sn_xml).root)
    assert [c.node_id for c in sn.children] == ["c1", "c2", "d1"]

    # PortConfig._claimed has no duplicate
    assert "IPV6_PORT_GATEWAY" in PortConfig._claimed


def test_services_and_audit_fixes() -> None:
    xml = (
        b"<PACKETTRACER5><NETWORK><DEVICES>"
        b"<DEVICE><WORKSPACE/></DEVICE>"  # engine is None
        b"<DEVICE><ENGINE><TYPE model='Server-PT'>Server</TYPE><NAME>SRV1</NAME>"
        b"<ACS_SERVER><USERS><USER><NAME>aaa_u</NAME></USER></USERS></ACS_SERVER>"
        b"<IOE_USER_MANAGER><USERS><USER><NAME>ioe_u</NAME></USER></USERS></IOE_USER_MANAGER>"
        b"<DHCP_SERVERS><ASSOCIATED_PORTS><ASSOCIATED_PORT><DHCP_SERVER>"
        b"<POOLS><POOL><NAME>p1</NAME><NETWORK>10.0.0.0</NETWORK><MASK>255.255.255.0</MASK></POOL></POOLS>"
        b"</DHCP_SERVER></ASSOCIATED_PORT></ASSOCIATED_PORTS></DHCP_SERVERS>"
        b"<DHCPV6_SERVER_LIST><ASSOCIATED_PORTS><ASSOCIATED_PORT><NAME>v6</NAME></ASSOCIATED_PORT></ASSOCIATED_PORTS></DHCPV6_SERVER_LIST>"
        b"<EMBEDDED><DNS_SERVER><NAMESERVER-DATABASE>"
        b"<RESOURCE-RECORD><TYPE>A</TYPE><NAME>a.local</NAME><IPADDRESS>10.0.0.1</IPADDRESS></RESOURCE-RECORD>"
        b"</NAMESERVER-DATABASE></DNS_SERVER></EMBEDDED>"
        b"</ENGINE></DEVICE>"
        b"</DEVICES><LINKS/></NETWORK></PACKETTRACER5>"
    )
    lab = Lab.from_bytes(xml)
    srv = lab.devices[1]
    assert srv.services is not None
    assert [u.name for u in srv.services.aaa_users] == ["aaa_u"]

    inv = inventory(lab)
    assert inv.aaa_users.raw == 1
    assert len(inv.dns_records_by_device) == 1
    assert inv.dns_records_by_device[0][0] == "SRV1"

    # format_identity on empty strings & 0-server summary
    assert format_identity(("", "")) == "<empty>"
    empty_lab = Lab.from_bytes(b"<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>")
    assert "x 0 servers" in inventory(empty_lab).summary()

    # _engine_views extracts model when passed <ENGINE> directly
    assert srv.engine is not None
    views = _engine_views(srv.engine)
    assert views[0][0] == "Server-PT"

    # strip_service_records preserves IOE_USER_MANAGER/USERS/USER and DHCPV6_SERVER_LIST bindings
    strip_service_records(srv)
    out = srv.to_xml()
    assert b"ioe_u" in out
    assert b"aaa_u" not in out
    assert b"<DHCPV6_SERVER_LIST><ASSOCIATED_PORTS><ASSOCIATED_PORT>" in out

    # sanitize_engine with leftovers and direct <ENGINE> extracts model automatically
    tmpl = TemplateLeftovers.from_templates({"Server-PT": xml.split(b"<DEVICE>")[2].split(b"</DEVICE>")[0].join([b"<DEVICE>", b"</DEVICE>"])})
    lab2 = Lab.from_bytes(xml)
    eng2 = lab2.devices[1].engine
    assert eng2 is not None
    rep = sanitize_engine(eng2, leftovers=tmpl)
    assert rep.removed.get("aaa-users") == 1
    assert b"ioe_u" in eng2.to_bytes()
    assert b"<DHCPV6_SERVER_LIST><ASSOCIATED_PORTS><ASSOCIATED_PORT>" in eng2.to_bytes()


def test_diff_and_export_fixes() -> None:
    lab_a = Lab.from_bytes(
        b"<PACKETTRACER5><NETWORK><DEVICES>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R1</NAME>"
        b"<RUNNINGCONFIG><LINE>a</LINE><LINE>b</LINE><LINE>!</LINE></RUNNINGCONFIG>"
        b"<MODULE><PORT><TYPE>GigE</TYPE><POWER>false</POWER><FULLDUPLEX>true</FULLDUPLEX></PORT></MODULE>"
        b"</ENGINE><WORKSPACE><LOGICAL><DEV_ADDR>1</DEV_ADDR></LOGICAL></WORKSPACE></DEVICE>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R2</NAME></ENGINE>"
        b"<WORKSPACE><LOGICAL><DEV_ADDR>2</DEV_ADDR></LOGICAL></WORKSPACE></DEVICE>"
        b"</DEVICES><LINKS>"
        b"<LINK><TYPE>eCopper</TYPE><CABLE><FROM>s1</FROM><TO>s2</TO>"
        b"<FROM_DEVICE_MEM_ADDR>1</FROM_DEVICE_MEM_ADDR><TO_DEVICE_MEM_ADDR>2</TO_DEVICE_MEM_ADDR>"
        b"<PORT>Gig0/0</PORT><PORT>Gig0/1</PORT><TYPE>eStraightThrough</TYPE></CABLE></LINK>"
        b"<LINK><TYPE>eWireless</TYPE></LINK>"
        b"<LINK><TYPE>eWireless</TYPE></LINK>"
        b"</LINKS></NETWORK></PACKETTRACER5>"
    )
    lab_b = Lab.from_bytes(
        b"<PACKETTRACER5><NETWORK><DEVICES>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R1</NAME>"
        b"<RUNNINGCONFIG><LINE>b</LINE><LINE>a</LINE><LINE>!</LINE><LINE>!</LINE></RUNNINGCONFIG>"
        b"<MODULE><PORT><TYPE>GigE</TYPE><POWER>false</POWER><FULLDUPLEX>true</FULLDUPLEX></PORT></MODULE>"
        b"</ENGINE><WORKSPACE><LOGICAL><DEV_ADDR>9</DEV_ADDR></LOGICAL></WORKSPACE></DEVICE>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R2</NAME></ENGINE>"
        b"<WORKSPACE><LOGICAL><DEV_ADDR>8</DEV_ADDR></LOGICAL></WORKSPACE></DEVICE>"
        b"</DEVICES><LINKS>"
        b"<LINK><TYPE>eCopper</TYPE><CABLE><FROM>x2</FROM><TO>x1</TO>"
        b"<FROM_DEVICE_MEM_ADDR>8</FROM_DEVICE_MEM_ADDR><TO_DEVICE_MEM_ADDR>9</TO_DEVICE_MEM_ADDR>"
        b"<PORT>Gig0/1</PORT><PORT>Gig0/0</PORT><TYPE>eStraightThrough</TYPE></CABLE></LINK>"
        b"<LINK><TYPE>eWireless</TYPE></LINK>"
        b"</LINKS></NETWORK></PACKETTRACER5>"
    )
    d = diff_labs(lab_a, lab_b)
    # Reordered/duplicated config lines detected via SequenceMatcher
    assert len(d.configs) == 1
    # Reversed cable endpoints match as identical; second wireless link detected as removed
    assert len(d.links) == 1
    assert d.links[0].removed is True

    # ExportError inheritance
    assert issubclass(ExportError, PacketTracerError)
    assert issubclass(ExportError, ValueError)

    # Graphviz single \n (not double-escaped \\n)
    dot = to_graphviz(lab_a)
    assert r'label="R1\nRouter 2911"' in dot
    assert r"\\n" not in dot

    # NetBox maps enabled to port.power (False even though FULLDUPLEX is true)
    nb = json.loads(to_netbox(lab_a))
    assert nb["devices"][0]["interfaces"][0]["enabled"] is False

    # Containerlab quotes scalars & deduplicates node keys
    dup_lab = Lab.from_bytes(
        b"<PACKETTRACER5><NETWORK><DEVICES>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R 1</NAME></ENGINE></DEVICE>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R/1</NAME></ENGINE></DEVICE>"
        b"</DEVICES><LINKS/></NETWORK></PACKETTRACER5>"
    )
    clab = to_containerlab(dup_lab, topology_name="my: lab #1")
    assert 'name: "my: lab #1"' in clab
    assert "    R-1:" in clab
    assert "    R-1-2:" in clab
    clab_links = to_containerlab(lab_a)
    assert '"R1:Gig0/0"' in clab_links


# --------------------------------------------------------------------------
# 3. Builder, CLI & Hooks
# --------------------------------------------------------------------------
def test_builder_fixes(tmp_path: Path) -> None:
    cached_models, cached_modules = load_device_templates()
    orig_len = len(cached_models)
    lab = BuilderLab()
    lab.models["__TEST_ONLY__"] = b""
    assert "__TEST_ONLY__" not in cached_models
    assert len(cached_models) == orig_len

    # Invalid model / pc_ip must not mutate counters or physical workspace
    before_n = lab._n
    before_pos = lab._pos
    with pytest.raises(KeyError):
        lab.add_device("NO_SUCH_MODEL", "BadDev")
    with pytest.raises(ValueError, match="pc_ip"):
        lab.add_device("PC-PT", "BadPC", pc_ip=("10.0.0.1", "255.255.255.0"))
    assert lab._n == before_n
    assert lab._pos == before_pos

    # Escaped name with & < and regex backreference \1
    sid = lab.add_device("PC-PT", r"PC&\1<1>")
    assert r"PC&\1<1>" in lab.device_names()

    # slot= forwarded in add_device and multi-module serial port resolution
    r1 = lab.add_device("2911", "R-SER-1", install="HWIC-2T", slot=0)
    lab.install_module(r1, "HWIC-2T", slot=1)
    r2 = lab.add_device("2911", "R-SER-2", install="HWIC-2T", slot=0)
    lab.link(r1, "Serial0/1/0", r2, "Serial0/0/0", kind="serial", dce=r1, clock=256000)

    r1_bays = [
        sl for sl in lab._els[r1].find("ENGINE").iter("SLOT")
        if sl.findtext("TYPE") == "eInterfaceCard"
    ]
    bay0_ports = [pt for pt in r1_bays[0].iter("PORT") if pt.findtext("TYPE") == "eSmartSerial"]
    bay1_ports = [pt for pt in r1_bays[1].iter("PORT") if pt.findtext("TYPE") == "eSmartSerial"]
    assert bay1_ports[0].findtext("CLOCKRATE") == "256000"
    assert bay0_ports[0].findtext("CLOCKRATE") != "256000"

    # link() validates kind and dce before appending <LINK>
    links_el = lab.net.find("LINKS")
    before_links = len(links_el.findall("LINK"))
    with pytest.raises(ValueError, match="kind"):
        lab.link(r1, "Gig0/0", r2, "Gig0/0", kind="fiber")
    with pytest.raises(ValueError, match="dce"):
        lab.link(r1, "Serial0/0/0", r2, "Serial0/0/0", kind="serial", dce=sid)
    assert len(links_el.findall("LINK")) == before_links

    # load_tier_map skips empty pattern lists
    tm = tmp_path / "tiers.json"
    tm.write_text(json.dumps({"empty_tier": [], "custom": ["^MY-"]}), encoding="utf-8")
    try:
        assert load_tier_map(tm) == 1
        assert tier_for_name("MY-HOST") == "custom"
        assert tier_for_name("OTHER-HOST") == "misc"
    finally:
        load_tier_map(None)


def test_cli_fixes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # --version
    with pytest.raises(SystemExit) as exc:
        cli_main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out

    # pkt info --json outputs pure JSON and hides key/iv for legacy
    legacy_pkt = tmp_path / "leg.pkt"
    legacy_pkt.write_bytes(encode_bytes(b"<PACKETTRACER5/>", fmt="legacy"))
    assert cli_main(["info", str(legacy_pkt), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["format"] == "legacy"
    assert "key_byte" not in payload and "iv_byte" not in payload

    assert cli_main(["info", str(legacy_pkt)]) == 0
    text_out = capsys.readouterr().out
    assert "key byte" not in text_out and "iv byte" not in text_out

    # pkt unpack deduplicates .cfg filenames
    dup_xml = (
        b"<PACKETTRACER5><NETWORK><DEVICES>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R 1</NAME>"
        b"<RUNNINGCONFIG><LINE>hostname a</LINE></RUNNINGCONFIG></ENGINE></DEVICE>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R/1</NAME>"
        b"<RUNNINGCONFIG><LINE>hostname b</LINE></RUNNINGCONFIG></ENGINE></DEVICE>"
        b"</DEVICES><LINKS/></NETWORK></PACKETTRACER5>"
    )
    dup_pkt = tmp_path / "dup.pkt"
    dup_pkt.write_bytes(encode_bytes(dup_xml))
    out_dir = tmp_path / "unpacked"
    assert cli_main(["unpack", str(dup_pkt), "-o", str(out_dir)]) == 0
    capsys.readouterr()
    cfgs = sorted(p.name for p in (out_dir / "configs").glob("*.cfg"))
    assert cfgs == ["R_1.cfg", "R_1_2.cfg"]

    # pkt diff exits 0 on metadata/layout-only diff and still emits --unified
    pkt_a = tmp_path / "a.pkt"
    pkt_b = tmp_path / "b.pkt"
    pkt_a.write_bytes(encode_bytes(b"<PACKETTRACER5><EXTRA>1</EXTRA></PACKETTRACER5>"))
    pkt_b.write_bytes(encode_bytes(b"<PACKETTRACER5><EXTRA>2</EXTRA></PACKETTRACER5>"))
    assert cli_main(["diff", str(pkt_a), str(pkt_b), "--unified"]) == 0
    diff_out = capsys.readouterr().out
    assert "+<PACKETTRACER5><EXTRA>2</EXTRA></PACKETTRACER5>" in diff_out


def test_rewrite_repo_links_hook_anchors_and_dirs() -> None:
    hook_path = Path(__file__).resolve().parent.parent / "hooks" / "rewrite_repo_links.py"
    spec = importlib.util.spec_from_file_location("rewrite_repo_links", hook_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    cfg = SimpleNamespace(config_file_path=str(hook_path.parent.parent / "mkdocs.yml"))
    md = "[file](../README.md#install) [dir](../tools/) [missing](../nope.txt)"
    out = mod.on_page_markdown(md, None, cfg, None)
    assert "/blob/main/README.md#install)" in out
    assert "/tree/main/tools)" in out
    assert "(../nope.txt)" in out


def test_new_audit_fixes_and_builder_coverage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import xml.etree.ElementTree as ET
    from pkt_core.builder.lab import (
        Layout,
        harvest_models,
        harvest_modules,
        kind_for_model,
        label_box,
        load_tier_map,
        normalise_device_power,
        parse_devices,
        tier_for_name,
    )
    from pkt_core.resources import load_device_templates

    # 1. All 78 bundled module templates parse cleanly as <SLOT> elements
    models, modules = load_device_templates()
    assert len(modules) >= 78
    for mod_name, mod_xml in modules.items():
        parsed = ET.fromstring(mod_xml)
        assert parsed.tag == "SLOT", mod_name

    # 2. Export & diff resolve SAVE_REF_ID endpoints on builder-authored labs
    blab = BuilderLab()
    blab.prune_seed_devices()
    r1 = blab.add_device(
        "2911",
        "R1",
        ios_config=["interface Serial0/0/0", " ip address 10.0.0.1 255.255.255.252", "end"],
        install="HWIC-2T",
    )
    r2 = blab.add_device("2911", "R2", install="HWIC-2T")
    blab.link(r1, "Serial0/0/0", r2, "Serial0/0/0", kind="serial", dce=r1, clock=128000)

    # Check DTE CLOCKRATEFLAG is "false" and DCE CLOCKRATEFLAG is "true", no duplicate interface block,
    # and dirty template IP 10.0.0.1 on HWIC-2T Port 0 was cleared!
    r1_el = blab._els[r1]
    r2_el = blab._els[r2]
    r1_ser = [p for p in r1_el.iter("PORT") if p.findtext("TYPE") == "eSmartSerial"][0]
    r2_ser = [p for p in r2_el.iter("PORT") if p.findtext("TYPE") == "eSmartSerial"][0]
    assert r1_ser.findtext("CLOCKRATE") == "128000"
    assert r1_ser.findtext("CLOCKRATEFLAG") == "true"
    assert r2_ser.findtext("CLOCKRATE") == "0"
    assert r2_ser.findtext("CLOCKRATEFLAG") == "false"
    assert (r1_ser.findtext("IP") or "") == ""
    assert (r2_ser.findtext("IP") or "") == ""
    rc_lines = [e.text or "" for e in r1_el.findall("ENGINE/RUNNINGCONFIG/LINE")]
    assert rc_lines.count("interface Serial0/0/0") == 1
    assert " clock rate 128000" in rc_lines

    # set_os, set_config_register, set_wireless
    blab.set_os(r1, image="c2900-universalk9-mz.SPA.151-4.M4.bin", file_name="c2900.bin")
    blab.set_os(r1, image="c2900-new.bin")
    blab.set_config_register(r1, "0x2142")
    blab.set_config_register(r1, 0x2102)
    assert r1_el.findtext("ENGINE/OS_IMAGE") == "c2900-new.bin"
    assert r1_el.findtext("ENGINE/OS_FILE_NAME") == "c2900.bin"
    assert r1_el.findtext("ENGINE/CONFIG_REGISTER") == str(0x2102)

    ap_id = blab.add_device("AccessPoint-PT", "AP1")
    w_count = blab.set_wireless(
        ap_id,
        ssid="CORP-WIFI",
        auth_type=1,
        encrypt_type=2,
        password="secret",
        userid="admin",
        channel=6,
        radio_band=1,
    )
    assert w_count >= 1
    assert blab._els[ap_id].findtext(".//SSID") == "CORP-WIFI"
    assert blab._els[ap_id].findtext(".//PORT[TYPE='eAccessPointWirelessG']/CHANNEL") == "6"
    lt_id = blab.add_device("Laptop-PT", "LT1")
    assert (
        blab.set_wireless(
            lt_id,
            ssid="CORP-WIFI",
            password="secret",
            userid="admin",
            channel=6,
        )
        >= 1
    )

    # 2-part serial port name (e.g. Router-PT with eSerial ports) and fallback serial port name
    rpt1 = blab.add_device("Router-PT", "RPT1")
    rpt2 = blab.add_device("Router-PT", "RPT2")
    blab.link(rpt1, "Serial2/0", rpt2, "Serial0", kind="serial", dce=rpt1, clock=64000)

    out_pkt = tmp_path / "built.pkt"
    blab.save(out_pkt)
    built_xml = decode_bytes(out_pkt.read_bytes()).xml
    mlab = Lab.from_bytes(built_xml)

    dot = to_graphviz(mlab)
    assert "R1" in dot and "R2" in dot
    assert "Serial0/0/0" in dot
    assert "->" in dot

    nb = json.loads(to_netbox(mlab))
    assert any(c["a"]["device"] == "R1" and c["b"]["device"] == "R2" for c in nb["cables"])
    clab = to_containerlab(mlab)
    assert '"R1:Serial0/0/0"' in clab and '"R2:Serial0/0/0"' in clab

    # 3. harvest_models & harvest_modules on tmp_path .pkt
    harvest_dir = tmp_path / "saves"
    harvest_dir.mkdir()
    (harvest_dir / "sample.pkt").write_bytes(out_pkt.read_bytes())
    (harvest_dir / "corrupt.pkt").write_bytes(b"not a pkt")
    h_models = harvest_models(harvest_dir, wanted={"2911"})
    assert "2911" in h_models
    h_modules = harvest_modules(harvest_dir, wanted={"HWIC-2T"})
    assert "HWIC-2T" in h_modules
    assert ET.fromstring(h_modules["HWIC-2T"]).tag == "SLOT"

    # normalise_device_power when <POWER> is absent or false
    blk_absent = b"<DEVICE><ENGINE><NAME>X</NAME></ENGINE></DEVICE>"
    norm_blk, was_off = normalise_device_power(blk_absent)
    assert was_off is True and b"<POWER>true</POWER>" in norm_blk

    # 4. Layout anchor, reserve, forget, page wrapping, and bounds errors
    with pytest.raises(ValueError, match="canvas bounds"):
        Layout(x_min=500, x_max=100)
    lay = Layout()
    assert label_box("router", "R1", "2911")[0] > 0
    for m_str, expected_kind in (
        ("Power Distribution Device", "pdd"),
        ("Sniffer", "sniffer"),
        ("Server-PT", "server"),
        ("AccessPoint-PT", "access-point"),
        ("Laptop-PT", "laptop"),
        ("PC-PT", "pc"),
        ("5505", "firewall"),
        ("2960-24TT", "switch"),
        ("3560-24PS", "multilayer-switch"),
        ("2911", "router"),
        ("Temperature Sensor", "iot"),
        ("Unknown-Widget-XYZ", "default"),
    ):
        assert kind_for_model(m_str) == expected_kind

    res_p = lay.reserve("RES-1", "2911", 4000, 200)
    assert res_p.page == 1
    lay.forget("RES-1")
    assert len(lay.placements) == 0

    lay.anchor("g1", 4100, 200)
    p1 = lay.place("G1-R1", "2911", group="g1")
    assert p1.page == 1
    p2 = lay.place("G1-R2", "2911", group="g1")
    assert p2.page == 1 and p2.x > p1.x

    small_lay = Layout(x_min=60, y_min=60, x_max=400, y_max=300)
    with pytest.raises(ValueError, match="does not fit"):
        small_lay.place("A" * 80, "2911")
    for idx in range(6):
        small_lay.place(f"D{idx}", "2911", group="wrap")

    # parse_devices edge cases
    assert parse_devices(b"<PACKETTRACER5/>") == []
    edge_xml = (
        b"<PACKETTRACER5><NETWORK><DEVICES>"
        b"<DEVICE/>"
        b"<DEVICE><ENGINE><NAME>NoWS</NAME></ENGINE></DEVICE>"
        b"<DEVICE><ENGINE><NAME>NoXY</NAME></ENGINE><WORKSPACE><LOGICAL/></WORKSPACE></DEVICE>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>OK</NAME></ENGINE>"
        b"<WORKSPACE><LOGICAL><X>10</X><Y>20</Y></LOGICAL></WORKSPACE></DEVICE>"
        b"</DEVICES></NETWORK></PACKETTRACER5>"
    )
    parsed_devs = parse_devices(edge_xml)
    assert len(parsed_devs) == 1 and parsed_devs[0].name == "OK"

    # load_tier_map rules list format & invalid format
    tm_rules = tmp_path / "tier_rules.json"
    tm_rules.write_text(
        json.dumps({"rules": [{"tier": "edge", "patterns": ["^EDGE-"]}]}),
        encoding="utf-8",
    )
    try:
        assert load_tier_map(tm_rules) == 1
        assert tier_for_name("EDGE-01") == "edge"
        assert tier_for_name("E767-01-RTR") == "airborne"
    finally:
        load_tier_map(None)

    tm_bad = tmp_path / "tier_bad.json"
    tm_bad.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="expected an object"):
        load_tier_map(tm_bad)

    # Lab.__init__ with bytes, .pkt path, and invalid seed
    blab_from_pkt = BuilderLab(out_pkt)
    assert "R1" in blab_from_pkt.device_names()
    with pytest.raises(ValueError, match="NETWORK"):
        BuilderLab(b"<PACKETTRACER5/>")
    with pytest.raises(ValueError, match="physical workspace"):
        BuilderLab(b"<PACKETTRACER5><NETWORK><DEVICES/></NETWORK></PACKETTRACER5>")

    # 5. detect_format with candidates=["legacy"], quncompress trailing bytes,
    # XML entity unescaping, PIs with quotes/>, self-closing <TAG a="1" / >, PktNode.__hash__
    leg_bytes = encode_bytes(b"<PACKETTRACER5/>", fmt="legacy")
    assert detect_format(leg_bytes, candidates=["pkt", "legacy"]) == "legacy"
    assert detect_format(leg_bytes, candidates=["legacy"]) == "legacy"
    with pytest.raises(FormatError):
        detect_format(b"12345678", candidates=["legacy"])

    with pytest.raises(CompressionError, match="trailing"):
        quncompress(qcompress(b"<ROOT/>") + b"trailing_garbage")

    sc_doc = parse_xml_bytes(b"<TAG a='1' / >")
    assert sc_doc.root.tag == "TAG"
    assert sc_doc.root.get("a") == "1"
    assert "/" not in [k.decode() for k, _, _ in sc_doc.root.attrs]

    pi_doc = parse_xml_bytes(b"<?pi don't > stop ?><TAG a='1'><br><CHILD/></TAG>")
    assert pi_doc.root.tag == "TAG"
    br_el = pi_doc.root.find("br")
    assert br_el is not None
    br_el.set("class", "clear")
    assert b'<br class="clear">' in pi_doc.to_bytes()

    # Entity round-trip on set/get and set_name/name
    pi_doc.root.set("label", 'a & b < c "d"')
    assert pi_doc.root.get("label") == 'a & b < c "d"'
    dev0 = mlab.devices[0]
    dev0.set_name("R&D <Lab>")
    assert dev0.name == "R&D <Lab>"
    dev0.set_name(dev0.name)
    assert dev0.name == "R&D <Lab>"
    assert len({dev0, mlab.devices[0]}) == 1

    # Missing <ENGINE> on <DEVICE> does not crash Device properties, diff_labs, or export
    bare_lab = Lab.from_bytes(
        b"<PACKETTRACER5><NETWORK><DEVICES><DEVICE/></DEVICES><LINKS/></NETWORK></PACKETTRACER5>"
    )
    bare_dev = bare_lab.devices[0]
    assert bare_dev.name == ""
    assert bare_dev.kind == ""
    assert bare_dev.model == ""
    assert bare_dev.custom_model == ""
    assert bare_dev.power_state == "absent"
    assert bare_dev.powered is False
    assert bare_dev.description == ""
    assert bare_dev.modules == []
    assert bare_dev.ports == []
    assert diff_labs(bare_lab, bare_lab).identical is True
    assert "digraph" in to_graphviz(bare_lab)

    # CLI unpack on legacy file omits key_byte/iv_byte, and diff on same XML in different formats
    leg_out = tmp_path / "leg_unpacked"
    assert cli_main(["unpack", str(legacy_pkt := tmp_path / "leg2.pkt"), "-o", str(leg_out)]) == 2
    capsys.readouterr()
    legacy_pkt.write_bytes(leg_bytes)
    assert cli_main(["unpack", str(legacy_pkt), "-o", str(leg_out)]) == 0
    capsys.readouterr()
    leg_meta = json.loads((leg_out / "leg2.container.json").read_text(encoding="utf-8"))
    assert "key_byte" not in leg_meta and "iv_byte" not in leg_meta

    mod_pkt = tmp_path / "mod2.pkt"
    mod_pkt.write_bytes(encode_bytes(b"<PACKETTRACER5/>", fmt="pkt"))
    assert cli_main(["diff", str(legacy_pkt), str(mod_pkt)]) == 0
    assert "outer format" in capsys.readouterr().out

