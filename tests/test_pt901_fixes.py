# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Regression tests for Cisco Packet Tracer 9.0.1 compatibility fixes."""
from __future__ import annotations

import base64
import gzip
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from pkt_core.audit import validate_lab
from pkt_core.grade import _extract_network_state, grade_lab
from pkt_core.models import Lab

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import activity  # noqa: E402
import scoring  # noqa: E402


def _wrap_pkt(devices_xml: str) -> bytes:
    xml = (
        "<PACKETTRACER5>"
        "<VERSION>9.0.1.0858</VERSION>"
        f"<NETWORK><DEVICES>{devices_xml}</DEVICES><LINKS/></NETWORK>"
        "</PACKETTRACER5>"
    )
    return xml.encode("utf-8")


def _wrap_pka(init_net_xml: str, ans_net_xml: str, init_tree: str, comp_tree: str) -> bytes:
    return (
        "<PACKETTRACER5_ACTIVITY>"
        "<VERSION>9.0.1.0858</VERSION>"
        f"{init_net_xml}"
        f"{init_net_xml}"
        f"{ans_net_xml}"
        f"{comp_tree}"
        f"{init_tree}"
        '<LOCKINGTREE enabled="no"/>'
        "<OPTIONS/>"
        '<ACTIVITY ENABLED="no" PASS="" TIMERTYPE="0"/>'
        "</PACKETTRACER5_ACTIVITY>"
    ).encode("utf-8")


def test_scoring_from_shapes_formats_newlines_check_types_and_tail_scaffold() -> None:
    shapes = json.loads(gzip.decompress((TOOLS / "device_shapes.json").read_bytes()).decode("utf-8"))
    spec = [
        {
            "name": "R9",
            "model": "2911",
            "overrides": {
                "Host Name": "R9",
                "Power": "1",
                "Ports/GigabitEthernet0/0/IP Address": "192.168.9.1",
                "Ports/GigabitEthernet0/0/Subnet Mask": "255.255.255.0",
                "Ports/GigabitEthernet0/0/Port Up": "1",
            },
        },
        {
            "name": "SW9",
            "model": "2960-24TT",
            "overrides": {
                "Ports/FastEthernet0/1/Dynamic Mode": "3",
                "Ports/Vlan1/IP Address": "1.1.1.2",
            },
        },
        {
            "name": "PC9",
            "model": "PC-PT",
            "overrides": {
                "Ports/FastEthernet0/IP Address": "192.168.9.10",
                "Default Gateway": "192.168.9.1",
            },
        },
    ]

    init_xml, comp_xml = scoring.from_shapes(spec, shapes=shapes)
    assert "</NODE><NODE>" not in init_xml
    assert "</NODE><NODE>" not in comp_xml
    assert "<COMPONENTS />" not in comp_xml
    assert "<POINTS />" not in comp_xml

    comp_root = ET.fromstring(comp_xml).find("NODE")
    assert comp_root is not None
    assert comp_root.find("NAME").get("checkType") == "1"

    top_names = [ch.findtext("NAME") for ch in comp_root.findall("NODE")]
    dev_idx = max(top_names.index("R9"), top_names.index("SW9"), top_names.index("PC9"))
    for tail_name in ("Remote Network", "Remote Networks", "Encircling Tests"):
        if tail_name in top_names:
            assert top_names.index(tail_name) > dev_idx

    r9_node = next(ch for ch in comp_root.findall("NODE") if ch.findtext("NAME") == "R9")
    assert r9_node.find("NAME").get("checkType") == "1"
    # Device-level Power="1" override must NOT mark a port Power leaf as checked unless explicitly targeted.
    for node in r9_node.iter("NODE"):
        if (node.findtext("ID") or "") == "GigabitEthernet0/0":
            for child in node.findall("NODE"):
                if (child.findtext("ID") or "") == "Power":
                    assert child.find("NAME").get("checkType") == "0"


def test_scoring_from_template_formats_newlines_and_tail_scaffold() -> None:
    tmpl = (
        "<PACKETTRACER5_ACTIVITY>"
        "<INITIALSETUP><NODE><NAME checkType=\"0\">Network</NAME><ID>Network</ID>"
        "<NODE><NAME checkType=\"0\">R_SRC</NAME><ID>R_SRC</ID>"
        "<NODE><NAME checkType=\"0\" nodeValue=\"R_SRC\">Host Name</NAME><ID>Host Name</ID></NODE>"
        "</NODE></NODE></INITIALSETUP>"
        "<COMPARISONS><NODE><NAME checkType=\"0\">Network</NAME><ID>Network</ID>"
        "<NODE><NAME checkType=\"0\">Instruction</NAME><ID>Instruction</ID></NODE>"
        "<NODE><NAME checkType=\"0\">Remote Networks</NAME><ID>Remote Networks</ID></NODE>"
        "<NODE><NAME checkType=\"0\">Encircling Tests</NAME><ID>Encircling Tests</ID></NODE>"
        "<NODE><NAME checkType=\"0\">R_SRC</NAME><ID>R_SRC</ID>"
        "<NODE><NAME checkType=\"0\" nodeValue=\"R_SRC\">Host Name</NAME><ID>Host Name</ID></NODE>"
        "</NODE></NODE></COMPARISONS>"
        "</PACKETTRACER5_ACTIVITY>"
    )
    init_xml, comp_xml = scoring.from_template(
        tmpl,
        devices=["R_SRC"],
        rename={"R_SRC": "R_DST"},
        overrides={"R_DST": {"Host Name": "R_DST"}},
    )
    assert "</NODE><NODE>" not in init_xml
    assert "</NODE><NODE>" not in comp_xml
    net = ET.fromstring(comp_xml).find("NODE")
    assert net is not None
    top_names = [ch.findtext("NAME") for ch in net.findall("NODE")]
    assert top_names == ["Instruction", "R_DST", "Remote Networks", "Encircling Tests"]


def test_scoring_derive_values_stops_at_end_maps_modes_and_prefers_engine_gateway() -> None:
    net_xml = _wrap_pkt(
        "<DEVICE><ENGINE><NAME>SW1</NAME><TYPE model=\"2960-24TT\">switch</TYPE><POWER>true</POWER>"
        "<RUNNINGCONFIG>"
        "<LINE>hostname GOOD-SW</LINE>"
        "<LINE>interface GigabitEthernet0/0</LINE>"
        "<LINE> ip address 10.0.0.1 255.255.255.0</LINE>"
        "<LINE> no shutdown</LINE>"
        "<LINE>interface FastEthernet0/1</LINE>"
        "<LINE> switchport mode access</LINE>"
        "<LINE>interface FastEthernet0/2</LINE>"
        "<LINE> switchport mode trunk</LINE>"
        "<LINE>end</LINE>"
        "<LINE>hostname AFTER-END</LINE>"
        "<LINE>interface GigabitEthernet0/0</LINE>"
        "<LINE> ip address 10.99.99.99 255.255.255.0</LINE>"
        "</RUNNINGCONFIG></ENGINE></DEVICE>"
        "<DEVICE><ENGINE><NAME>SRV1</NAME><TYPE model=\"Server-PT\">server</TYPE><POWER>true</POWER>"
        "<GATEWAY>10.1.1.1</GATEWAY>"
        "<MODULE><PORT><IP>10.1.1.10</IP><SUBNET>255.255.255.0</SUBNET>"
        "<PORT_GATEWAY>10.9.9.9</PORT_GATEWAY></PORT></MODULE>"
        "</ENGINE></DEVICE>"
    )
    vals = scoring.derive_values(net_xml)
    sw = vals["SW1"]
    assert sw["Host Name"] == "GOOD-SW"
    assert sw["Ports/GigabitEthernet0/0/IP Address"] == "10.0.0.1"
    assert sw["Ports/FastEthernet0/1/Dynamic Mode"] == "3"
    assert sw["Ports/FastEthernet0/2/Dynamic Mode"] == "2"
    assert vals["SRV1"]["Default Gateway"] == "10.1.1.1"


def test_activity_set_load_init_tree() -> None:
    act = activity.Activity(TOOLS / "activity_skeleton.xml")
    act.set_load_init_tree(False)
    assert "<LOAD_INIT_TREE>false</LOAD_INIT_TREE>" in act.xml
    act.set_load_init_tree(True)
    assert "<LOAD_INIT_TREE>true</LOAD_INIT_TREE>" in act.xml


def test_audit_config_after_end() -> None:
    bad_lab = Lab.from_bytes(
        _wrap_pkt(
            "<DEVICE><ENGINE><NAME>SW1</NAME><TYPE model=\"3650-24PS\">multilayerswitch</TYPE>"
            "<POWER>true</POWER><RUNNINGCONFIG>"
            "<LINE>hostname SW1</LINE><LINE>end</LINE><LINE>router bgp 65010</LINE>"
            "</RUNNINGCONFIG></ENGINE></DEVICE>"
        )
    )
    report = validate_lab(bad_lab)
    assert any(f.severity == "fail" and f.code == "config-after-end" for f in report.findings)

    ok_lab = Lab.from_bytes(
        _wrap_pkt(
            "<DEVICE><ENGINE><NAME>SW1</NAME><TYPE model=\"3650-24PS\">multilayerswitch</TYPE>"
            "<POWER>true</POWER><RUNNINGCONFIG>"
            "<LINE>hostname SW1</LINE><LINE>end</LINE><LINE>!</LINE>"
            "</RUNNINGCONFIG></ENGINE></DEVICE>"
        )
    )
    report_ok = validate_lab(ok_lab)
    assert not any(f.code == "config-after-end" for f in report_ok.findings)


def test_audit_end_device_gateway_mismatch() -> None:
    for eng_gw in ("", "0.0.0.0", "10.0.0.2"):
        lab = Lab.from_bytes(
            _wrap_pkt(
                f"<DEVICE><ENGINE><NAME>SRV1</NAME><TYPE model=\"Server-PT\">server</TYPE>"
                f"<POWER>true</POWER><GATEWAY>{eng_gw}</GATEWAY>"
                "<MODULE><PORT><IP>10.0.0.10</IP><SUBNET>255.255.255.0</SUBNET>"
                "<PORT_GATEWAY>10.0.0.1</PORT_GATEWAY></PORT></MODULE>"
                "</ENGINE></DEVICE>"
            )
        )
        rep = validate_lab(lab)
        assert any(
            f.severity == "warn" and f.code == "end-device-gateway-mismatch"
            for f in rep.findings
        ), f"Expected warning for eng_gw={eng_gw!r}"

    matched_lab = Lab.from_bytes(
        _wrap_pkt(
            "<DEVICE><ENGINE><NAME>SRV1</NAME><TYPE model=\"Server-PT\">server</TYPE>"
            "<POWER>true</POWER><GATEWAY>10.0.0.1</GATEWAY>"
            "<MODULE><PORT><IP>10.0.0.10</IP><SUBNET>255.255.255.0</SUBNET>"
            "<PORT_GATEWAY>10.0.0.1</PORT_GATEWAY></PORT></MODULE>"
            "</ENGINE></DEVICE>"
        )
    )
    assert not any(f.code == "end-device-gateway-mismatch" for f in validate_lab(matched_lab).findings)


def test_audit_scoring_adjacent_nodes() -> None:
    net = "<PACKETTRACER5><NETWORK><DEVICES/><LINKS/></NETWORK></PACKETTRACER5>"
    bad_comp = (
        "<COMPARISONS><NODE><NAME>Network</NAME>"
        "<NODE><NAME>A</NAME></NODE><NODE><NAME>B</NAME></NODE>"
        "</NODE></COMPARISONS>"
    )
    good_init = "<INITIALSETUP><NODE><NAME>Network</NAME></NODE></INITIALSETUP>"
    bad_pka = Lab.from_bytes(_wrap_pka(net, net, good_init, bad_comp))
    assert any(
        f.severity == "fail" and f.code == "scoring-adjacent-nodes"
        for f in validate_lab(bad_pka).findings
    )

    good_comp = (
        "<COMPARISONS><NODE><NAME>Network</NAME>\n"
        "<NODE><NAME>A</NAME></NODE>\n<NODE><NAME>B</NAME></NODE>\n"
        "</NODE></COMPARISONS>"
    )
    good_pka = Lab.from_bytes(_wrap_pka(net, net, good_init, good_comp))
    assert not any(f.code == "scoring-adjacent-nodes" for f in validate_lab(good_pka).findings)


def test_grade_engine_gateway_strict_precedence() -> None:
    ans_net = _wrap_pkt(
        "<DEVICE><ENGINE><NAME>SRV1</NAME><TYPE model=\"Server-PT\">server</TYPE>"
        "<POWER>true</POWER><GATEWAY>10.10.10.1</GATEWAY>"
        "<MODULE><PORT><TYPE>eCopperFastEthernet</TYPE>"
        "<IP>10.10.10.10</IP><SUBNET>255.255.255.0</SUBNET>"
        "<PORT_GATEWAY>10.10.10.1</PORT_GATEWAY></PORT></MODULE>"
        "</ENGINE></DEVICE>"
    ).decode("utf-8")

    for bad_eng_gw in ("", "0.0.0.0"):
        stu_net = _wrap_pkt(
            f"<DEVICE><ENGINE><NAME>SRV1</NAME><TYPE model=\"Server-PT\">server</TYPE>"
            f"<POWER>true</POWER><GATEWAY>{bad_eng_gw}</GATEWAY>"
            "<MODULE><PORT><TYPE>eCopperFastEthernet</TYPE>"
            "<IP>10.10.10.10</IP><SUBNET>255.255.255.0</SUBNET>"
            "<PORT_GATEWAY>10.10.10.1</PORT_GATEWAY></PORT></MODULE>"
            "</ENGINE></DEVICE>"
        ).decode("utf-8")
        init_tree = "<INITIALSETUP><NODE><NAME>Network</NAME></NODE></INITIALSETUP>"
        comp_tree = "<COMPARISONS><NODE><NAME>Network</NAME></NODE></COMPARISONS>"
        stu_lab = Lab.from_bytes(_wrap_pka(stu_net, ans_net, init_tree, comp_tree))
        rep = grade_lab(stu_lab, against=stu_lab)
        gw_items = [it for it in rep.items if it.item == "Default Gateway"]
        assert gw_items and not gw_items[0].passed
        assert gw_items[0].actual == bad_eng_gw


def test_grade_stops_at_end_dynamic_mode_vlan_svi_and_ios_extractors() -> None:
    lab = Lab.from_bytes(
        _wrap_pkt(
            "<DEVICE><ENGINE><NAME>CORE1</NAME><TYPE model=\"3650-24PS\">multilayerswitch</TYPE>"
            "<POWER>true</POWER>"
            "<MODULE><PORT><TYPE>eCopperFastEthernet</TYPE></PORT></MODULE>"
            "<RUNNINGCONFIG>"
            "<LINE>hostname CORE1</LINE>"
            "<LINE>service password-encryption</LINE>"
            "<LINE>aaa new-model</LINE>"
            "<LINE>ntp authenticate</LINE>"
            "<LINE>ntp update-calendar</LINE>"
            "<LINE>ip ssh version 2</LINE>"
            "<LINE>vtp domain CORP</LINE>"
            "<LINE>spanning-tree mode rapid-pvst</LINE>"
            "<LINE>interface FastEthernet0/1</LINE>"
            "<LINE> switchport mode access</LINE>"
            "<LINE>interface FastEthernet0/2</LINE>"
            "<LINE> switchport mode trunk</LINE>"
            "<LINE>interface FastEthernet0/3</LINE>"
            "<LINE>interface Vlan10</LINE>"
            "<LINE> ip address 10.10.10.1 255.255.255.0</LINE>"
            "<LINE>interface Vlan20</LINE>"
            "<LINE> ip address 10.20.20.1 255.255.255.0</LINE>"
            "<LINE> shutdown</LINE>"
            "<LINE>router ospf 1</LINE>"
            "<LINE> router-id 1.1.1.1</LINE>"
            "<LINE> auto-cost reference-bandwidth 10000</LINE>"
            "<LINE>router bgp 65010</LINE>"
            "<LINE> bgp router-id 2.2.2.2</LINE>"
            "<LINE> bgp log-neighbor-changes</LINE>"
            "<LINE> no synchronization</LINE>"
            "<LINE>end</LINE>"
            "<LINE>hostname BOGUS-AFTER-END</LINE>"
            "<LINE>router bgp 65099</LINE>"
            "</RUNNINGCONFIG></ENGINE></DEVICE>"
        )
    )
    assert lab.network is not None
    st = _extract_network_state(lab.network)["CORE1"]
    f = st.flat_props
    assert f["Host Name"] == "CORE1"
    assert f["Service Password Encryption"] == "1"
    assert f["AAA/New-model"] == "1"
    assert f["NTP/NTP Authenticate"] == "1"
    assert f["NTP/Update Calendar"] == "1"
    assert f["SSH Server/SSH Server Version"] == "2"
    assert f["VTP/Domain Name"] == "CORP"
    assert f["STP/RSTP"] == "1"
    assert f["OSPF/1/Router ID"] == "1.1.1.1"
    assert f["OSPF/1/Auto Cost"] == "10000"
    assert f["BGP/Autonomous System"] == "65010"
    assert f["BGP/Router ID"] == "2.2.2.2"
    assert f["BGP/Log Neighbor Changes"] == "1"
    assert f["BGP/Synchronization"] == "0"
    assert f["Ports/FastEthernet0/1/Dynamic Mode"] == "3"
    assert f["Ports/FastEthernet0/2/Dynamic Mode"] == "2"
    assert f["Ports/FastEthernet0/3/Dynamic Mode"] == "1"
    assert f["Ports/Vlan10/Port Up"] == "1"
    assert f["Ports/Vlan20/Port Up"] == "0"


def test_grade_explicit_comparisons_with_components_category() -> None:
    ans_net = _wrap_pkt(
        "<DEVICE><ENGINE><NAME>SW1</NAME><TYPE model=\"2960-24TT\">switch</TYPE>"
        "<POWER>true</POWER><RUNNINGCONFIG>"
        "<LINE>hostname SW1</LINE>"
        "<LINE>vtp domain CORP</LINE>"
        "<LINE>interface FastEthernet0/1</LINE>"
        "<LINE> switchport mode access</LINE>"
        "<LINE>end</LINE></RUNNINGCONFIG></ENGINE></DEVICE>"
    ).decode("utf-8")
    init_tree = "<INITIALSETUP><NODE><NAME>Network</NAME><ID>Network</ID></NODE></INITIALSETUP>"
    comp_tree = (
        "<COMPARISONS><NODE><NAME checkType=\"1\">Network</NAME><ID>Network</ID>"
        "<NODE><NAME checkType=\"1\">SW1</NAME><ID>SW1</ID>"
        "<NODE><NAME checkType=\"1\">VTP</NAME><ID>VTP</ID>"
        "<NODE><NAME checkType=\"2\" nodeValue=\"CORP\">Domain Name</NAME><ID>Domain Name</ID>"
        "<COMPONENTS>Switching</COMPONENTS><POINTS>3</POINTS></NODE>"
        "</NODE>"
        "<NODE><NAME checkType=\"1\">Ports</NAME><ID>Ports</ID>"
        "<NODE><NAME checkType=\"1\">FastEthernet0/1</NAME><ID>FastEthernet0/1</ID>"
        "<NODE><NAME checkType=\"2\" nodeValue=\"3\">Dynamic Mode</NAME><ID>Dynamic Mode</ID>"
        "<COMPONENTS>Switching</COMPONENTS><POINTS>2</POINTS></NODE>"
        "</NODE></NODE></NODE></NODE></COMPARISONS>"
    )
    stu_lab = Lab.from_bytes(_wrap_pka(ans_net, ans_net, init_tree, comp_tree))
    rep = grade_lab(stu_lab, against=stu_lab)
    assert rep.points_earned == 5
    assert rep.points_possible == 5
    assert all(it.category == "Switching" for it in rep.items)


def test_refreshed_iot_templates_and_sync() -> None:
    tools_raw = (TOOLS / "device_templates.json").read_bytes()
    pkg_raw = (REPO / "src" / "pkt_core" / "data" / "device_templates.json").read_bytes()
    assert tools_raw == pkg_raw

    expected_times = {
        "Battery": "1690224453107",
        "CO Detector": "1490842172927",
        "Metal Sensor": "1690222433077",
        "Servo": "1689805864180",
        "Solar Panel": "1689907057935",
        "Sound Sensor": "1690222433077",
        "Street Lamp": "1750888775422",
        "Trip Wire": "1689883111562",
        "Water Level Monitor": "1689890871095",
        "Webcam": "1727285900528",
        "Wind Turbine": "1689917766346",
    }
    models = json.loads(tools_raw.decode("utf-8"))["models"]
    for model, expected_tct in expected_times.items():
        xml = gzip.decompress(base64.b64decode(models[model])).decode("utf-8")
        m = re.search(r"<TEMPLATE_CREATION_TIME>(.*?)</TEMPLATE_CREATION_TIME>", xml)
        assert m is not None and m.group(1) == expected_tct
        ET.fromstring(xml)
