# SPDX-License-Identifier: GPL-3.0-or-later
"""The packaged data files and the authoring entry point they make possible."""

from __future__ import annotations

import os

import pytest

from pkt_core import Lab, decode, load_templates, resources
from pkt_core.models import Lab as LabModel


def test_device_templates_are_bundled() -> None:
    models, modules = resources.load_device_templates()
    assert "2911" in models
    assert "2960-24TT" in models
    assert models["2911"].startswith(b"<DEVICE")
    assert modules


def test_device_templates_are_cached() -> None:
    # A lab build reads the 829 KB library once; a second call must not re-parse it.
    assert resources.load_device_templates() is resources.load_device_templates()


def test_device_templates_path_points_at_the_library() -> None:
    path = resources.device_templates_path()
    assert os.path.isfile(path)
    assert path.endswith("device_templates.json")


def test_network_seed_is_a_container_document() -> None:
    xml = resources.load_network_seed()
    assert b"<PACKETTRACER5>" in xml
    assert b"<DEVICES>" in xml


def test_network_seed_is_cached() -> None:
    assert resources.load_network_seed() is resources.load_network_seed()


def test_load_templates_defaults_to_the_bundled_library() -> None:
    models, modules = load_templates()
    assert "2911" in models
    assert load_templates(resources.device_templates_path())[0]["2911"] == models["2911"]


def test_lab_builds_from_the_bundled_seed(tmp_path) -> None:
    """The whole point: a lab can be built with no checkout and no arguments."""
    lab = Lab()
    lab.prune_seed_devices()
    router = lab.add_device(
        "2911",
        "R1",
        ios_config=["hostname R1", "end"],
    )
    switch = lab.add_device("2960-24TT", "SW1")
    lab.link(router, "GigabitEthernet0/0", switch, "GigabitEthernet0/1")

    out = tmp_path / "built.pkt"
    lab.save(out)

    container = decode(out)
    assert container.root_tag == "PACKETTRACER5"
    names = [d.name for d in LabModel.from_bytes(container.xml).devices]
    assert names == ["R1", "SW1"]


def test_local_device_names_do_not_need_the_seed(tmp_path) -> None:
    lab = Lab()
    lab.prune_seed_devices()
    lab.add_device("PC-PT", "PC1", pc_ip=("192.168.1.10", "255.255.255.0", "192.168.1.1"))
    lab.save(tmp_path / "pc.pkt")
    names = [d.name for d in LabModel.from_bytes(decode(tmp_path / "pc.pkt").xml).devices]
    assert names == ["PC1"]


def test_unknown_model_raises(tmp_path) -> None:
    lab = Lab()
    lab.prune_seed_devices()
    with pytest.raises(KeyError):
        lab.add_device("NOT-A-MODEL", "X1")
