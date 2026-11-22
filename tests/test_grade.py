# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the headless .pka / .pkt auto-grader (pkt_core.grade & pkt grade)."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sys
from typing import Any, Sequence
import xml.etree.ElementTree as ET

import pytest

from pkt_core import (
    DeviceScore,
    GradeItem,
    GradeReport,
    Lab as BuilderLab,
    decode,
    encode_bytes,
    grade_batch,
    grade_bytes,
    grade_file,
    grade_lab,
)
from pkt_core.cli.main import main as cli_main
from pkt_core.grade import _extract_network_state
from pkt_core.models import Device, Lab as ModelLab


def _build_topo_xml(*, configured: bool, wrong_ip: bool = False, extra_features: bool = False) -> bytes:
    blab = BuilderLab()
    blab.prune_seed_devices()

    r1_ip = "192.168.9.99" if wrong_ip else "192.168.9.1"
    r1_cfg = (
        [
            "!",
            "version 15.1",
            "hostname R9",
            "enable secret cisco123",
            "ip routing",
            "ipv6 unicast-routing",
            "!",
            "ip dhcp pool LAN_POOL",
            " network 192.168.9.0 255.255.255.0",
            " default-router 192.168.9.1",
            "!",
            "interface GigabitEthernet0/0",
            " description LAN-Gateway",
            f" ip address {r1_ip} 255.255.255.0",
            " ipv6 address 2001:DB8:9::1/64",
            " ip helper-address 10.0.0.10",
            " ip access-group LAN_IN in",
            " ip access-group LAN_OUT out",
            " ip ospf 1 area 0",
            " no shutdown",
            "!",
            "interface GigabitEthernet0/0.10",
            " encapsulation dot1Q 10",
            "!",
            "interface Serial0/0/0",
            " ip address 10.0.0.1 255.255.255.252",
            " clock rate 128000",
            " no shutdown",
            "!",
            "router ospf 1",
            " network 192.168.9.0 0.0.0.255 area 0",
            "!",
            "ip route 10.99.0.0 255.255.0.0 10.0.0.2",
            "!",
            "end",
        ]
        if configured
        else None
    )

    sw_cfg = (
        [
            "!",
            "hostname SW9",
            "ip default-gateway 192.168.9.1",
            "vlan 10",
            " name ENG",
            "!",
            "interface GigabitEthernet0/1",
            " switchport mode trunk",
            " switchport trunk native vlan 99",
            " no shutdown",
            "!",
            "interface FastEthernet0/1",
            " switchport mode access",
            " switchport access vlan 10",
            " switchport voice vlan 20",
            " no shutdown",
            "!",
            "end",
        ]
        if (configured and extra_features)
        else (["!", "hostname SW9", "end"] if configured else None)
    )

    r1 = blab.add_device("2911", "R9", 200, 200, ios_config=r1_cfg, install="HWIC-2T")
    r2 = blab.add_device("2911", "R10", 400, 200, install="HWIC-2T")
    sw = blab.add_device("2960-24TT", "SW9", 200, 380, ios_config=sw_cfg)
    pc = blab.add_device(
        "PC-PT",
        "PC9",
        200,
        520,
        pc_ip=(("192.168.9.10", "255.255.255.0", "192.168.9.1") if configured else None),
    )

    blab.link(r1, "GigabitEthernet0/0", sw, "GigabitEthernet0/1")
    blab.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
    if configured:
        blab.link(r1, "Serial0/0/0", r2, "Serial0/0/0", kind="serial", dce=r1, clock=128000)

    if extra_features and configured:
        srv_id = blab.add_device("Server-PT", "SRV9", 420, 520)
        srv_el = blab._els[srv_id]
        eng = srv_el.find("ENGINE")
        assert eng is not None
        # Add DNS record, DHCP pool, and AAA client
        nd = eng.find(".//NAMESERVER-DATABASE")
        if nd is not None:
            rr = ET.SubElement(nd, "RESOURCE-RECORD")
            ET.SubElement(rr, "NAME").text = "intranet.local"
            ET.SubElement(rr, "IPADDRESS").text = "192.168.9.50"
            ET.SubElement(rr, "TYPE").text = "0"
        pools = eng.find(".//DHCP_SERVER/POOLS")
        if pools is not None:
            p_el = ET.SubElement(pools, "POOL")
            ET.SubElement(p_el, "NAME").text = "SRV_POOL"
            ET.SubElement(p_el, "NETWORK").text = "192.168.9.0"
            ET.SubElement(p_el, "MASK").text = "255.255.255.0"
            ET.SubElement(p_el, "DEFAULT_ROUTER").text = "192.168.9.1"
        acs = eng.find("ACS_SERVER")
        if acs is not None:
            en = acs.find("ENABLED")
            if en is not None:
                en.text = "1"
            cl_wrap = acs.find("ACS_CLIENTS")
            if cl_wrap is not None:
                c_el = ET.SubElement(cl_wrap, "CLIENT")
                ET.SubElement(c_el, "HOST_IP").text = "192.168.9.1"
                ET.SubElement(c_el, "SERVER_TYPE").text = "Radius"

    return ET.tostring(blab.base, encoding="utf-8")


def _build_pka_bytes(
    *,
    working_xml: bytes,
    initial_xml: bytes,
    answer_xml: bytes,
) -> bytes:
    tools_dir = str(Path(__file__).resolve().parent.parent / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    import activity
    import scoring

    shapes = scoring.load_shapes(Path(tools_dir) / "device_shapes.json")
    vals = scoring.derive_values(answer_xml)
    score_spec = [
        {"name": "R9", "model": "2911", "overrides": vals.get("R9", {})},
        {"name": "SW9", "model": "2960-24TT", "overrides": vals.get("SW9", {})},
        {"name": "PC9", "model": "PC-PT", "overrides": vals.get("PC9", {})},
    ]
    init_sc, comp_sc = scoring.from_shapes(score_spec, shapes)
    act = activity.Activity(Path(tools_dir) / "activity_skeleton.xml")
    act.set_feedback(incomplete="Keep working!", complete="All checks passed!")
    act.set_scoring_xml(init_sc, comp_sc)
    act.set_networks(initial_xml=initial_xml, answer_xml=answer_xml)
    # Replace block 0 (working network) with working_xml
    blocks = list(activity.PKT.finditer(act.xml))
    b0 = blocks[0]
    act.xml = act.xml[: b0.start()] + working_xml.decode("utf-8") + act.xml[b0.end() :]
    return encode_bytes(act.xml.encode("utf-8"), fmt="pkt")


def test_pka_embedded_and_master_grading(tmp_path: Path) -> None:
    initial_xml = _build_topo_xml(configured=False)
    answer_xml = _build_topo_xml(configured=True, extra_features=True)
    partial_xml = _build_topo_xml(configured=True, wrong_ip=True, extra_features=True)

    master_pka = tmp_path / "master.pka"
    solved_pka = tmp_path / "solved.pka"
    unsolved_pka = tmp_path / "unsolved.pka"
    partial_pka = tmp_path / "partial.pka"

    master_pka.write_bytes(
        _build_pka_bytes(working_xml=initial_xml, initial_xml=initial_xml, answer_xml=answer_xml)
    )
    solved_pka.write_bytes(
        _build_pka_bytes(working_xml=answer_xml, initial_xml=initial_xml, answer_xml=answer_xml)
    )
    unsolved_pka.write_bytes(
        _build_pka_bytes(working_xml=initial_xml, initial_xml=initial_xml, answer_xml=answer_xml)
    )
    partial_pka.write_bytes(
        _build_pka_bytes(working_xml=partial_xml, initial_xml=initial_xml, answer_xml=answer_xml)
    )

    # 1. Solved activity scores 100%
    rep_solved = grade_file(solved_pka)
    assert rep_solved.passed is True
    assert rep_solved.percentage == 100.0
    assert rep_solved.points_earned == rep_solved.points_possible > 0
    assert rep_solved.items_failed == 0
    assert rep_solved.feedback == "All checks passed!"
    assert "PASS" in rep_solved.summary(show_passed=True)

    # 2. Unsolved activity scores < 100% and lists missed items
    rep_unsolved = grade_file(unsolved_pka)
    assert rep_unsolved.passed is False
    assert rep_unsolved.percentage < 100.0
    assert rep_unsolved.items_failed > 0
    assert rep_unsolved.feedback == "Keep working!"
    assert "FAIL" in rep_unsolved.summary()

    # 3. Tamper-proof grading against master.pka catches a student who overwrote their answer_xml
    tampered_pka = tmp_path / "tampered.pka"
    tampered_pka.write_bytes(
        _build_pka_bytes(working_xml=initial_xml, initial_xml=initial_xml, answer_xml=initial_xml)
    )
    rep_against_master = grade_file(tampered_pka, against=master_pka)
    assert rep_against_master.mode == "pka-master"
    assert rep_against_master.passed is False
    assert rep_against_master.percentage < 100.0

    # 4. Partial submission detects exact wrong IP on GigabitEthernet0/0
    rep_partial = grade_file(partial_pka, against=master_pka)
    assert rep_partial.passed is False
    failed_paths = {f.path: f for f in rep_partial.failed_items}
    assert "R9/Ports/GigabitEthernet0/0/IP Address" in failed_paths
    ip_miss = failed_paths["R9/Ports/GigabitEthernet0/0/IP Address"]
    assert ip_miss.expected == "192.168.9.1"
    assert ip_miss.actual == "192.168.9.99"

    # With pass_threshold=80.0, partial submission passes
    rep_partial_80 = grade_file(partial_pka, against=master_pka, pass_threshold=80.0)
    assert rep_partial_80.passed is True


def test_pkt_against_solution_and_explicit_tree_only(tmp_path: Path) -> None:
    start_xml = _build_topo_xml(configured=False)
    done_xml = _build_topo_xml(configured=True, extra_features=True)

    student_pkt = tmp_path / "student.pkt"
    solution_pkt = tmp_path / "solution.pkt"
    student_pkt.write_bytes(encode_bytes(start_xml))
    solution_pkt.write_bytes(encode_bytes(done_xml))

    # Grading a plain .pkt without --against raises ValueError
    with pytest.raises(ValueError, match="do not embed an answer network"):
        grade_file(student_pkt)

    # Grading solution against solution passes 100%
    rep_ok = grade_file(solution_pkt, against=solution_pkt)
    assert rep_ok.mode == "pkt-against-solution"
    assert rep_ok.passed is True
    assert rep_ok.percentage == 100.0

    # Grading student against solution with category filter
    rep_ip = grade_bytes(
        start_xml,
        against=done_xml,
        categories=["Ip"],
    )
    assert all(it.category == "Ip" for it in rep_ip.items)
    assert rep_ip.passed is False

    # Explicit <COMPARISONS> tree with checkType="1" and no answer network, plus INITIALSETUP diff
    tree_only_xml = (
        b"<PACKETTRACER5_ACTIVITY>"
        b"<VERSION>9.0.1.0858</VERSION>"
        b"<PACKETTRACER5><VERSION>9.0.1.0858</VERSION><NETWORK><DEVICES>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R1</NAME>"
        b"<POWER>true</POWER>"
        b"<RUNNINGCONFIG>"
        b"<LINE>hostname R1-WRONG</LINE>"
        b"<LINE>no ip routing</LINE>"
        b"<LINE>interface Gi0/0</LINE>"
        b"<LINE> shutdown</LINE>"
        b"</RUNNINGCONFIG>"
        b"</ENGINE></DEVICE>"
        b"</DEVICES><LINKS/></NETWORK></PACKETTRACER5>"
        b"<COMPARISONS><NODE><NAME checkType='1' eclass='8' headNode='true'>Network</NAME><ID>Network</ID>"
        b"<NODE><NAME>Instruction</NAME><ID>Instruction</ID></NODE>"
        b"<NODE><NAME checkType='1'>R1</NAME><ID>R1</ID>"
        b"<NODE><NAME checkType='1' nodeValue='2911'>Device Model</NAME><ID>Device Model</ID><POINTS>2</POINTS></NODE>"
        b"<NODE><NAME checkType='1' nodeValue='R1' incorrectFeedback='Fix hostname'>Host Name</NAME><ID>Host Name</ID><POINTS>3</POINTS></NODE>"
        b"<NODE><NAME checkType='0'>Ports</NAME><ID>Ports</ID>"
        b"<NODE><NAME checkType='0'>GigabitEthernet0/0</NAME><ID>GigabitEthernet0/0</ID>"
        b"<NODE><NAME checkType='1' nodeValue='Connects to Gi0/1'>Link to SW1</NAME><ID>Link to SW1</ID><POINTS>1</POINTS></NODE>"
        b"<NODE><NAME checkType='1' nodeValue='10'>Access VLAN</NAME><ID>Access VLAN</ID><POINTS>1</POINTS></NODE>"
        b"<NODE><NAME checkType='1' nodeValue='10.0.0.1'>IP Address</NAME><ID>IP Address</ID><POINTS>1</POINTS></NODE>"
        b"</NODE></NODE>"
        b"<NODE><NAME checkType='0'>VLANS</NAME><ID>VLANS</ID>"
        b"<NODE><NAME checkType='1' nodeValue='10'>10</NAME><ID>10</ID><POINTS>1</POINTS></NODE>"
        b"</NODE>"
        b"<NODE><NAME checkType='0'>OSPF</NAME><ID>OSPF</ID>"
        b"<NODE><NAME checkType='1' nodeValue='1'>Process</NAME><ID>Process</ID><POINTS>1</POINTS></NODE>"
        b"</NODE>"
        b"<NODE><NAME checkType='0'>ACL</NAME><ID>ACL</ID>"
        b"<NODE><NAME checkType='1' nodeValue='100'>100</NAME><ID>100</ID><POINTS>1</POINTS></NODE>"
        b"</NODE>"
        b"</NODE></NODE></COMPARISONS>"
        b"<INITIALSETUP><NODE><NAME>Network</NAME><ID>Network</ID>"
        b"<NODE><NAME>Instruction</NAME><ID>Instruction</ID></NODE>"
        b"<NODE><NAME>R1</NAME><ID>R1</ID>"
        b"<NODE><NAME nodeValue='Router'>Host Name</NAME><ID>Host Name</ID><POINTS>1</POINTS></NODE>"
        b"</NODE></NODE></INITIALSETUP>"
        b"<COMPONENT_LIST>Ip, Routing, Switching</COMPONENT_LIST>"
        b"</PACKETTRACER5_ACTIVITY>"
    )
    tree_lab = ModelLab.from_bytes(tree_only_xml)
    assert tree_lab.component_list == ("Ip", "Routing", "Switching")
    assert tree_lab.working_lab.devices[0].name == "R1"
    assert tree_lab.initial_lab is None
    assert tree_lab.answer_lab is None
    sn0 = tree_lab.scoring_tree[0]
    assert sn0.check_type == 1
    assert sn0.eclass == 8
    assert sn0.head_node is True
    assert sn0.override_db_grading is False
    assert sn0.variable_enabled is False
    assert sn0.variable_name == ""

    rep_tree = grade_bytes(tree_only_xml)
    assert rep_tree.points_possible == 11
    assert rep_tree.points_earned == 2
    assert rep_tree.failed_items[0].feedback == "Fix hostname"
    assert "Fix hostname" in rep_tree.summary()
    assert "feedback" in rep_tree.failed_items[0].as_dict()

    # Also test diff-from-INITIALSETUP tree mode when checkType == 0 everywhere
    diff_tree_xml = (
        b"<PACKETTRACER5_ACTIVITY>"
        b"<PACKETTRACER5><NETWORK><DEVICES>"
        b"<DEVICE><ENGINE><TYPE model='2911'>Router</TYPE><NAME>R1</NAME>"
        b"<POWER>true</POWER>"
        b"<RUNNINGCONFIG><LINE>hostname R1</LINE></RUNNINGCONFIG>"
        b"</ENGINE></DEVICE>"
        b"</DEVICES><LINKS/></NETWORK></PACKETTRACER5>"
        b"<COMPARISONS><NODE><NAME checkType='0'>Network</NAME><ID>Network</ID>"
        b"<NODE><NAME checkType='0'>R1</NAME><ID>R1</ID>"
        b"<NODE><NAME checkType='0' nodeValue='R1' incorrectFeedback='Need R1'>Host Name</NAME><ID>Host Name</ID><POINTS>2</POINTS></NODE>"
        b"</NODE></NODE></COMPARISONS>"
        b"<INITIALSETUP><NODE><NAME>Network</NAME><ID>Network</ID>"
        b"<NODE><NAME>R1</NAME><ID>R1</ID>"
        b"<NODE><NAME nodeValue='Router'>Host Name</NAME><ID>Host Name</ID><POINTS>2</POINTS></NODE>"
        b"</NODE></NODE></INITIALSETUP>"
        b"</PACKETTRACER5_ACTIVITY>"
    )
    rep_diff_tree = grade_bytes(diff_tree_xml)
    assert rep_diff_tree.passed is True
    assert rep_diff_tree.points_earned == 2

    # Zero-point DeviceScore & GradeReport percentage edge case
    ds0 = DeviceScore(device="X", model="2911", points_earned=0, points_possible=0, items_passed=0, items_total=0)
    assert ds0.percentage == 100.0
    gr0 = GradeReport(target="t", mode="m", points_earned=0, points_possible=0, items=(), devices=())
    assert gr0.percentage == 100.0


def test_batch_grading_and_cli_grade(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    initial_xml = _build_topo_xml(configured=False)
    answer_xml = _build_topo_xml(configured=True)

    master_pka = tmp_path / "master.pka"
    sub1_pka = tmp_path / "sub1.pka"
    sub2_pka = tmp_path / "sub2.pka"

    master_pka.write_bytes(
        _build_pka_bytes(working_xml=initial_xml, initial_xml=initial_xml, answer_xml=answer_xml)
    )
    sub1_pka.write_bytes(
        _build_pka_bytes(working_xml=answer_xml, initial_xml=initial_xml, answer_xml=answer_xml)
    )
    sub2_pka.write_bytes(
        _build_pka_bytes(working_xml=initial_xml, initial_xml=initial_xml, answer_xml=answer_xml)
    )

    assert grade_batch([]) == []
    batch_reps = grade_batch([sub1_pka, sub2_pka], against=master_pka, max_workers=2)
    assert len(batch_reps) == 2
    assert batch_reps[0].passed is True
    assert batch_reps[1].passed is False

    # CLI single file --json
    assert cli_main(["grade", str(sub1_pka), "--json"]) == 0
    single_json = json.loads(capsys.readouterr().out)
    assert single_json["passed"] is True
    assert single_json["percentage"] == 100.0

    # CLI batch with --against, --csv, --categories, --show-passed
    csv_out = tmp_path / "grades" / "gradebook.csv"
    rc = cli_main(
        [
            "grade",
            str(sub1_pka),
            str(sub2_pka),
            "--against",
            str(master_pka),
            "--categories",
            "Ip,Routing",
            "--show-passed",
            "--csv",
            str(csv_out),
        ]
    )
    assert rc == 1
    out_txt = capsys.readouterr().out
    assert "batch: 1/2 passed" in out_txt
    assert csv_out.is_file()
    with csv_out.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2
    assert rows[0]["passed"] == "True"
    assert rows[1]["passed"] == "False"

    # CLI batch --json
    assert cli_main(["grade", str(sub1_pka), str(sub2_pka), "--json"]) == 1
    batch_json = json.loads(capsys.readouterr().out)
    assert batch_json["total_submissions"] == 2
    assert batch_json["passed_submissions"] == 1


# --------------------------------------------------------------------------- #
# interface admin state & port-name guessing
# --------------------------------------------------------------------------- #
SAMPLE_LAB = Path(__file__).resolve().parent.parent / "corpus" / "samples" / "sample_lab.pkt"
requires_sample_lab = pytest.mark.skipif(
    not SAMPLE_LAB.exists(), reason="committed sample_lab.pkt is missing"
)

R1_SUBIF_10 = (
    "interface GigabitEthernet0/1.10",
    " encapsulation dot1Q 10",
    " ip address 10.10.10.1 255.255.255.0",
    "!",
)


def _sample_lab_with_r1_lines(lines: Sequence[str]) -> ModelLab:
    """``sample_lab.pkt`` with ``lines`` added to R1's running config, right
    before ``interface GigabitEthernet0/2``."""
    xml = decode(SAMPLE_LAB).xml
    rc_start = xml.index(b"<RUNNINGCONFIG>", xml.index(b">R1</NAME>"))
    rc_end = xml.index(b"</RUNNINGCONFIG>", rc_start)
    at = xml.index(b"<LINE>interface GigabitEthernet0/2</LINE>", rc_start, rc_end)
    added = b"".join(b"<LINE>" + line.encode("utf-8") + b"</LINE>" for line in lines)
    return ModelLab.from_bytes(xml[:at] + added + xml[at:])


def _stock_device_lab(model: str, **kwargs: Any) -> ModelLab:
    """A one-device lab (device name ``DUT``) from the bundled ``model`` template."""
    blab = BuilderLab()
    blab.prune_seed_devices()
    blab.add_device(model, "DUT", 100, 100, **kwargs)
    return ModelLab.from_bytes(ET.tostring(blab.base, encoding="utf-8"))


def _config_interfaces(dev: Device) -> set[str]:
    return {
        line.split()[1].decode("utf-8")
        for line in dev.running_config
        if line.startswith(b"interface ")
    }


@requires_sample_lab
def test_running_config_interface_without_shutdown_line_is_up() -> None:
    """PT saves `show running-config` output, which never prints `no shutdown`."""
    lab = _sample_lab_with_r1_lines(
        R1_SUBIF_10
        + (
            "interface GigabitEthernet0/1.20",
            " encapsulation dot1Q 20",
            " ip address 10.20.20.1 255.255.255.0",
            " shutdown",
            "!",
        )
    )
    r1 = _extract_network_state(lab.network)["R1"].flat_props
    assert r1["Ports/GigabitEthernet0/1.10/IP Address"] == "10.10.10.1"
    assert r1["Ports/GigabitEthernet0/1.10/Port Up"] == "1"
    # an explicit `shutdown` still wins
    assert r1["Ports/GigabitEthernet0/1.20/Port Up"] == "0"
    assert r1["Ports/GigabitEthernet0/2/Port Up"] == "0"
    assert r1["Ports/Vlan1/Port Up"] == "0"


@pytest.mark.parametrize(
    ("model", "iface", "ip", "up"),
    [
        ("1841", "Serial0/0/0", "10.0.0.1", "1"),
        ("1841", "Loopback0", "1.1.1.1", "1"),
        ("1841", "FastEthernet0/0", "", "0"),  # template config: ` shutdown`
        ("2811", "FastEthernet0/0", "5.1.1.1", "1"),
        ("ISR4331", "GigabitEthernet0/0/0", "192.168.1.1", "1"),
    ],
)
def test_stock_router_interfaces_are_up_unless_shut_down(
    model: str, iface: str, ip: str, up: str
) -> None:
    flat = _extract_network_state(_stock_device_lab(model).network)["DUT"].flat_props
    assert flat[f"Ports/{iface}/IP Address"] == ip
    assert flat[f"Ports/{iface}/Port Up"] == up


@pytest.mark.parametrize("model", ["1841", "2811", "ISR4331", "2960-24TT", "3560-24PS"])
def test_port_name_guessing_never_invents_interfaces(model: str) -> None:
    """A <PORT> carries no name, so a guessed one must not create an interface
    the device does not have (e.g. FastEthernet0 on a router, or the 0-based
    FastEthernet0/0 on a 2960, whose ports start at Fa0/1)."""
    # pc_ip puts an address on the first <PORT>, which is what triggers a guess
    lab = _stock_device_lab(model, pc_ip=("10.9.9.9", "255.255.255.0", "10.9.9.1"))
    dev = lab.network.devices[0]
    state = _extract_network_state(lab.network)["DUT"]
    assert set(state.interfaces) <= _config_interfaces(dev)


def test_router_port_guess_uses_slot_numbering() -> None:
    """A router's first FastEthernet <PORT> is FastEthernet0/0, not FastEthernet0.

    The config only says `ip address dhcp`, so the leased address held on the
    2811 template's first <PORT> (5.1.1.1) is the one fact the XML adds.
    """
    lab = _stock_device_lab(
        "2811",
        ios_config=["hostname DUT", "interface FastEthernet0/0", " ip address dhcp", "!", "end"],
    )
    state = _extract_network_state(lab.network)["DUT"]
    assert state.flat_props["Ports/FastEthernet0/0/IP Address"] == "5.1.1.1"
    assert state.flat_props["Ports/FastEthernet0/0/Port Up"] == "1"
    assert set(state.interfaces) == {"FastEthernet0/0"}


@requires_sample_lab
def test_fastethernet0_alias_is_only_for_end_devices() -> None:
    states = _extract_network_state(ModelLab.from_bytes(decode(SAMPLE_LAB).xml).network)
    assert states["PC-A"].flat_props["Ports/FastEthernet0/IP Address"] == "192.168.1.10"
    assert states["Server"].flat_props["Ports/FastEthernet0/IP Address"] == "192.168.4.10"
    for router in ("R1", "R2"):
        assert "FastEthernet0" not in states[router].interfaces


# --------------------------------------------------------------------------- #
# no credit for an interface the student never configured
# --------------------------------------------------------------------------- #
@requires_sample_lab
def test_missing_subinterface_is_not_credited_from_another_interface() -> None:
    solution = _sample_lab_with_r1_lines(R1_SUBIF_10)
    student = ModelLab.from_bytes(decode(SAMPLE_LAB).xml)
    assert grade_lab(solution, against=solution).percentage == 100.0

    report = grade_lab(student, against=solution)
    prefix = "R1/Ports/GigabitEthernet0/1.10/"
    subif = {it.path[len(prefix):]: it for it in report.items if it.path.startswith(prefix)}
    assert set(subif) == {"IP Address", "Subnet Mask", "Port Up"}
    for leaf, item in subif.items():
        assert not item.passed, f"{leaf!r} credited for an interface the student never made"
        assert item.actual == "", f"{leaf!r} shows another interface's value"
