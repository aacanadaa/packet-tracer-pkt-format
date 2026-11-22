"""Tests for topology export and semantic diff."""

from __future__ import annotations

import json
from typing import Sequence

import pytest

from pkt_core.diff import diff_labs
from pkt_core.export import EXPORTERS, ExportError, export
from pkt_core.models import Lab

SAMPLE_A = """<PACKETTRACER5>
 <VERSION>7.3.1.0362</VERSION>
 <NETWORK>
  <DEVICES>
   <DEVICE>
    <ENGINE>
     <TYPE model="2960-24TT" customModel="">Switch</TYPE>
     <NAME translate="true">Switch0</NAME>
     <POWER>true</POWER>
     <MODULE><PORT><TYPE>eCopperFastEthernet</TYPE><MACADDRESS>00E0.A3D0.EC01</MACADDRESS></PORT></MODULE>
    </ENGINE>
    <WORKSPACE><LOGICAL><X>100</X><Y>200</Y><DEVCLUSTERID>1-1</DEVCLUSTERID><DEV_ADDR>111</DEV_ADDR></LOGICAL></WORKSPACE>
   </DEVICE>
   <DEVICE>
    <ENGINE>
     <TYPE model="PC-PT" customModel="">Pc</TYPE>
     <NAME translate="true">PC0</NAME>
     <POWER>true</POWER>
    </ENGINE>
    <WORKSPACE><LOGICAL><X>300</X><Y>200</Y><DEVCLUSTERID>1-1</DEVCLUSTERID><DEV_ADDR>222</DEV_ADDR></LOGICAL></WORKSPACE>
   </DEVICE>
  </DEVICES>
  <LINKS>
   <LINK>
    <TYPE>eCopper</TYPE>
    <CABLE>
     <LENGTH>5</LENGTH>
     <FROM>save-ref-id:111</FROM><PORT>FastEthernet0/1</PORT><FROM_DEVICE_MEM_ADDR>111</FROM_DEVICE_MEM_ADDR>
     <TO>save-ref-id:222</TO><PORT>FastEthernet0</PORT><TO_DEVICE_MEM_ADDR>222</TO_DEVICE_MEM_ADDR>
     <TYPE>eStraightThrough</TYPE>
    </CABLE>
   </LINK>
  </LINKS>
 </NETWORK>
</PACKETTRACER5>
"""

# Same devices, but PC0 moved and the link cable type changed.
SAMPLE_B = SAMPLE_A.replace("<X>300</X>", "<X>999</X>").replace(
    "eStraightThrough", "eCrossOver"
)


@pytest.fixture(scope="module")
def lab_a() -> Lab:
    return Lab.from_bytes(SAMPLE_A.encode("utf-8"))


@pytest.fixture(scope="module")
def lab_b() -> Lab:
    return Lab.from_bytes(SAMPLE_B.encode("utf-8"))


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------
def test_all_formats_registered() -> None:
    assert set(EXPORTERS) == {"graphviz", "netbox", "containerlab"}


def test_graphviz_contains_nodes_and_edges(lab_a: Lab) -> None:
    dot = export(lab_a, "graphviz")
    assert dot.startswith("digraph")
    assert "Switch0" in dot
    assert "PC0" in dot
    assert "->" in dot
    assert dot.rstrip().endswith("}")


def test_netbox_is_valid_json(lab_a: Lab) -> None:
    payload = json.loads(export(lab_a, "netbox"))
    assert payload["format"] == "pkt-core/netbox-inventory"
    names = [d["name"] for d in payload["devices"]]
    assert names == ["Switch0", "PC0"]
    assert payload["cables"][0]["type"] == "eStraightThrough"


def test_containerlab_has_valid_yaml_keys(lab_a: Lab) -> None:
    yml = export(lab_a, "containerlab")
    assert "name: pkt" in yml
    # device names must be identifier-like, so no raw spaces in node keys
    for line in yml.splitlines():
        if line.startswith("    ") and line.rstrip().endswith(":"):
            key = line.strip().rstrip(":")
            assert key and " " not in key, f"bad YAML key: {key!r}"


def test_export_is_read_only(lab_a: Lab) -> None:
    before = lab_a.to_xml()
    for fmt in EXPORTERS:
        export(lab_a, fmt)
    assert lab_a.to_xml() == before


def test_unknown_format_raises() -> None:
    with pytest.raises(ExportError):
        export(Lab.from_bytes(SAMPLE_A.encode("utf-8")), "nope")


# --------------------------------------------------------------------------
# Diff
# --------------------------------------------------------------------------
def test_diff_identical_is_empty(lab_a: Lab) -> None:
    d = diff_labs(lab_a, lab_a)
    assert d.identical is True
    assert d.summary_lines() == []


def test_diff_detects_position_and_cable_change(lab_a: Lab, lab_b: Lab) -> None:
    d = diff_labs(lab_a, lab_b)
    assert d.identical is False
    text = "\n".join(d.summary_lines())
    assert "PC0" in text
    assert "999" in text, "canvas X change should be reported"
    assert "eCrossOver" in text, "cable type change should be reported"


def test_diff_detects_added_and_removed_devices() -> None:
    added = SAMPLE_A.replace("</DEVICES>",
        '<DEVICE><ENGINE><TYPE model="1841" customModel="">Router</TYPE>'
        '<NAME translate="true">R1</NAME><POWER>true</POWER></ENGINE></DEVICE></DEVICES>')
    d = diff_labs(
        Lab.from_bytes(SAMPLE_A.encode("utf-8")),
        Lab.from_bytes(added.encode("utf-8")),
    )
    lines = d.summary_lines()
    assert any(line.startswith("+ device R1") for line in lines)

    removed = SAMPLE_A.replace(
        '<NAME translate="true">PC0</NAME>', '<NAME translate="true">PC99</NAME>'
    )
    d2 = diff_labs(
        Lab.from_bytes(SAMPLE_A.encode("utf-8")),
        Lab.from_bytes(removed.encode("utf-8")),
    )
    text = "\n".join(d2.summary_lines())
    assert "- device PC0" in text and "+ device PC99" in text


def test_diff_is_independent_of_device_order() -> None:
    """Reordering devices is not a semantic change."""
    import re

    swapped = re.sub(
        r"(<DEVICE>.*?</DEVICE>)(\s*)(<DEVICE>.*?</DEVICE>)",
        r"\3\2\1",
        SAMPLE_A,
        count=1,
        flags=re.S,
    )
    d = diff_labs(
        Lab.from_bytes(SAMPLE_A.encode("utf-8")),
        Lab.from_bytes(swapped.encode("utf-8")),
    )
    assert d.identical is True


def test_diff_reports_config_line_changes() -> None:
    a = """<PACKETTRACER5><NETWORK><DEVICES><DEVICE><ENGINE>
<TYPE model="2960" customModel="">Switch</TYPE><NAME>S1</NAME>
<RUNNINGCONFIG><LINE>hostname S1</LINE><LINE>banner motd \x03hi\x03</LINE></RUNNINGCONFIG>
</ENGINE></DEVICE></DEVICES></NETWORK></PACKETTRACER5>"""
    b = a.replace("<LINE>hostname S1</LINE>", "<LINE>hostname CORE</LINE>")
    d = diff_labs(Lab.from_bytes(a.encode("utf-8")), Lab.from_bytes(b.encode("utf-8")))
    text = "\n".join(d.summary_lines())
    assert "config S1" in text
    assert "hostname CORE" in text
    # control bytes must be compared as bytes, never normalised away
    assert "banner motd" not in text, "unchanged banner line must not be reported"


def _router_xml(*modules: Sequence[tuple[str, str]]) -> bytes:
    """One router whose <MODULE>s hold ``(port type, MAC)`` ports, in order."""
    mods = "".join(
        "<MODULE>"
        + "".join(
            f"<PORT><TYPE>{ptype}</TYPE><MACADDRESS>{mac}</MACADDRESS></PORT>"
            for ptype, mac in ports
        )
        + "</MODULE>"
        for ports in modules
    )
    return (
        "<PACKETTRACER5><NETWORK><DEVICES><DEVICE><ENGINE>"
        '<TYPE model="2911" customModel="">Router</TYPE><NAME>R1</NAME>'
        f"{mods}</ENGINE></DEVICE></DEVICES></NETWORK></PACKETTRACER5>"
    ).encode("utf-8")


def test_diff_matches_ports_by_mac() -> None:
    """Adding a module must not renumber, and so "change", every later port."""
    gi = "eCopperGigabitEthernet"
    # serial ports share Gi0/0's MAC, as R2's do in corpus/samples/sample_lab.pkt
    onboard = [(gi, "0001.0001.0001"), (gi, "0001.0001.0002"), ("eSmartSerial", "0001.0001.0001")]
    before = Lab.from_bytes(_router_xml(onboard))

    with_module = Lab.from_bytes(_router_xml([(gi, "0002.0002.0001")], onboard))
    [dev] = diff_labs(before, with_module).devices
    assert list(dev.port_changes) == ["0002.0002.0001"]
    assert dev.port_changes["0002.0002.0001"][0] == ""  # added, nothing else moved

    # a duplicate MAC gets its own counted key instead of overwriting the first
    retyped = [(gi, "0001.0001.0001"), (gi, "0001.0001.0002"), ("eSerial", "0001.0001.0001")]
    [dev] = diff_labs(before, Lab.from_bytes(_router_xml(retyped))).devices
    assert list(dev.port_changes) == ["0001.0001.0001 #2"]

    # a port without a MAC falls back to its position
    [dev] = diff_labs(
        Lab.from_bytes(_router_xml([("eSmartSerial", "")])),
        Lab.from_bytes(_router_xml([("eSerial", "")])),
    ).devices
    assert set(dev.port_changes) == {"0:eSmartSerial", "0:eSerial"}
