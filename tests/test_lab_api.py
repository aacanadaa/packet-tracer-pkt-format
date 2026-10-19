#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Tests for tools/lab_api.py -- device-name collisions and seed pruning.

The seed (tools/network_seed.xml) contributes pre-existing devices (SW1, R1,
R2, PC-A, PC-B, Server, Power Distribution Device0).  Naming a generated
device after one of them used to silently produce a duplicate; `add_device()`
now refuses by default and `prune_seed_devices()` drops the inherited devices
for a clean workspace.
"""
from __future__ import annotations

import importlib.util
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))  # pt9 (same convention as tests/test_pt9.py)
TOOLS = REPO / "tools"


def _load_lab_api():
    spec = importlib.util.spec_from_file_location("lab_api", TOOLS / "lab_api.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lab_api = _load_lab_api()

# names the shipped seed is known to contribute (the original collision report)
SEED_NAMES = {"SW1", "R1", "R2", "PC-A", "PC-B", "Server", "Power Distribution Device0"}


@pytest.fixture(scope="module")
def templates():
    return lab_api.load_templates(str(TOOLS / "device_templates.json"))


@pytest.fixture()
def lab(templates):
    models, modules = templates
    return lab_api.Lab(str(TOOLS / "network_seed.xml"), models, modules)


def _device_count(lab) -> int:
    return len(lab.devs.findall("DEVICE"))


# --------------------------------------------------------------------------- #
# device_names()
# --------------------------------------------------------------------------- #
def test_device_names_lists_seed_devices(lab):
    names = lab.device_names()
    assert len(names) == _device_count(lab)
    assert SEED_NAMES.issubset(set(names)), f"seed names missing from {names}"


def test_device_names_includes_added_devices(lab):
    before = set(lab.device_names())
    lab.add_device("2911", "R9")
    after = set(lab.device_names())
    assert after - before == {"R9"}


def test_unnamed_routers_and_switches_use_default_convention(lab):
    lab.prune_seed_devices()
    router1 = lab.add_device("2911")
    router2 = lab.add_device("ISR4331")
    switch1 = lab.add_device("2960-24TT")
    switch2 = lab.add_device("3560-24PS")

    assert [lab._els[sid].findtext("ENGINE/NAME")
            for sid in (router1, router2, switch1, switch2)] == [
                "R1", "R2", "SW1", "SW2",
            ]


def test_default_names_skip_names_already_in_seed(lab):
    router = lab.add_device("2911")
    switch = lab.add_device("2960-24TT")

    assert lab._els[router].findtext("ENGINE/NAME") == "R3"
    assert lab._els[switch].findtext("ENGINE/NAME") == "SW2"


def test_explicit_device_name_overrides_convention(lab):
    router = lab.add_device("2911", "EDGE-RTR")
    switch = lab.add_device("2960-24TT", "DIST-SW")

    assert lab._els[router].findtext("ENGINE/NAME") == "EDGE-RTR"
    assert lab._els[switch].findtext("ENGINE/NAME") == "DIST-SW"


def test_unnamed_non_network_device_requires_name(lab):
    with pytest.raises(ValueError, match="device name is required"):
        lab.add_device("PC-PT")


def test_save_watermarks_all_ios_routers_and_switches(lab, monkeypatch):
    lab.add_device(
        "2911", "R9",
        ios_config=["hostname R9", "ip domain-name old.example", "end"],
    )
    encoded = {}
    monkeypatch.setattr(
        lab_api.pt9, "encode",
        lambda _path, xml, _fmt: encoded.update(xml=xml),
    )

    lab.save("unused.pkt")

    root = ET.fromstring(encoded["xml"])
    devices = root.find("NETWORK/DEVICES").findall("DEVICE")
    for device in devices:
        engine = device.find("ENGINE")
        model = engine.find("TYPE").get("model", "")
        if lab_api.kind_for_model(model) in lab_api._IOS_DEVICE_KINDS:
            commands = [
                line.text for line in engine.findall("RUNNINGCONFIG/LINE")
                if (line.text or "").strip().lower().startswith("ip domain-name")
            ]
            assert commands == ["ip domain-name gjay.co.uk"]
        else:
            assert not any(
                (line.text or "").strip().lower().startswith("ip domain-name")
                for line in engine.findall("RUNNINGCONFIG/LINE")
            )


# --------------------------------------------------------------------------- #
# add_device() collision detection
# --------------------------------------------------------------------------- #
def test_add_device_rejects_seed_name(lab):
    n_before = _device_count(lab)
    with pytest.raises(ValueError, match="already in use") as exc:
        lab.add_device("2911", "SW1")
    assert "SW1" in str(exc.value)
    # a rejected name must not leave a half-added device behind
    assert _device_count(lab) == n_before
    assert "SW1(1)" not in lab.device_names()


def test_add_device_rejects_duplicate_generated_name(lab):
    lab.add_device("2911", "R9")
    with pytest.raises(ValueError, match="already in use"):
        lab.add_device("2911", "R9")
    assert lab.device_names().count("R9") == 1


def test_add_device_rejects_name_added_by_suffixing(lab):
    lab.add_device("2911", "R9")
    lab.add_device("2911", "R9", on_name_conflict="suffix")  # -> R9(1)
    with pytest.raises(ValueError, match="already in use"):
        lab.add_device("2911", "R9(1)")


def test_add_device_suffix_auto_renames(lab):
    sid0 = lab.add_device("2911", "R9")
    sid1 = lab.add_device("2911", "R9", on_name_conflict="suffix")
    sid2 = lab.add_device("2911", "R9", on_name_conflict="suffix")
    assert len({sid0, sid1, sid2}) == 3
    names = lab.device_names()
    assert names.count("R9") == 1
    assert names.count("R9(1)") == 1
    assert names.count("R9(2)") == 1


def test_add_device_suffix_on_seed_name(lab):
    lab.add_device("2960-24TT", "SW1", on_name_conflict="suffix")
    names = lab.device_names()
    assert "SW1(1)" in names
    assert names.count("SW1") == 1  # the seed's own SW1, untouched


def test_add_device_rejects_unknown_conflict_policy(lab):
    with pytest.raises(ValueError, match="on_name_conflict"):
        lab.add_device("2911", "R9", on_name_conflict="rename-silently")


# --------------------------------------------------------------------------- #
# prune_seed_devices()
# --------------------------------------------------------------------------- #
def test_prune_seed_devices_removes_only_the_seed(lab):
    seed = set(lab.device_names())
    lab.add_device("2911", "R9")
    lab.add_device("PC-PT", "PC9")
    removed = lab.prune_seed_devices()
    assert set(removed) == seed
    assert lab.device_names() == ["R9", "PC9"]
    assert _device_count(lab) == 2


def test_prune_seed_devices_is_idempotent(lab):
    lab.add_device("2911", "R9")
    lab.prune_seed_devices()
    assert lab.prune_seed_devices() == []
    assert lab.device_names() == ["R9"]


def test_prune_seed_devices_frees_seed_names(lab):
    lab.prune_seed_devices()
    lab.add_device("2911", "SW1")  # no ValueError any more
    assert "SW1" in lab.device_names()


def test_drop_seed_devices_is_an_alias(lab):
    assert lab_api.Lab.drop_seed_devices is lab_api.Lab.prune_seed_devices
    lab.add_device("2911", "R9")
    assert set(lab.drop_seed_devices()) == SEED_NAMES
    assert lab.device_names() == ["R9"]


def test_prune_seed_devices_removes_links_to_seed_devices(lab):
    seed_id = lab.initial_id()
    sid = lab.add_device("2911", "R9")
    lab.link(seed_id, "GigabitEthernet0/0", sid, "GigabitEthernet0/0")
    links = lab.net.find("LINKS")
    assert links is not None
    assert any(L.find("CABLE").findtext("FROM") == seed_id for L in links.findall("LINK"))
    lab.prune_seed_devices()
    # no dangling link may reference a removed seed device (orphan links corrupt
    # the file); the seed's own inter-device links go with their devices
    for L in links.findall("LINK"):
        cab = L.find("CABLE")
        assert seed_id not in (cab.findtext("FROM"), cab.findtext("TO"))
        assert sid in (cab.findtext("FROM"), cab.findtext("TO"))


def test_prune_seed_devices_keeps_generated_links(lab):
    a = lab.add_device("2911", "R9")
    b = lab.add_device("2960-24TT", "SW9")
    lab.prune_seed_devices()
    lab.link(a, "GigabitEthernet0/0", b, "GigabitEthernet0/1")
    links = lab.net.find("LINKS")
    assert links is not None and len(links.findall("LINK")) == 1
    cab = links.find("LINK/CABLE")
    assert cab.findtext("FROM") == a and cab.findtext("TO") == b
