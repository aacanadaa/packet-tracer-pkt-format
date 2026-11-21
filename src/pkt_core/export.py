"""Topology export to standard tooling formats.

These render the *model* (devices, ports, links) rather than the raw XML, so
they are inherently lossy with respect to Packet Tracer metadata — by design.
Round-tripping a lab is done with :mod:`pkt_core.codec`; exporting is for
interoperability.
"""

from __future__ import annotations

import json
from typing import Callable

from pkt_core.errors import PacketTracerError
from pkt_core.models import Device, Lab, Link

__all__ = [
    "EXPORTERS",
    "export",
    "to_graphviz",
    "to_netbox",
    "to_containerlab",
    "ExportError",
]


class ExportError(PacketTracerError, ValueError):
    """An unknown export format was requested."""


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


_YAML_RESERVED = frozenset({"true", "false", "yes", "no", "on", "off", "null", "~"})


def _yaml_quote(value: str) -> str:
    """Safely render a YAML scalar, double-quoting anything not a bare identifier."""
    if (
        value
        and value.lower() not in _YAML_RESERVED
        and (value[0].isalpha() or value[0] == "_")
        and all(ch.isalnum() or ch in "-_" for ch in value)
    ):
        return value
    return json.dumps(value, ensure_ascii=False)


def _yaml_key(value: str) -> str:
    """Make a device name safe as a YAML mapping key.

    Packet Tracer allows spaces and punctuation in device names
    (``"Power Distribution Device0"``); containerlab node names must be
    identifier-like.
    """
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in value)
    return cleaned.strip("-") or "unnamed"


def _nodes(lab: Lab) -> list[Device]:
    return lab.devices


def _edges(lab: Lab) -> list[Link]:
    return lab.links


def _endpoint_map(lab: Lab, values: list[str] | None = None) -> dict[str, str]:
    """Map every endpoint identifier a cable may use onto per-device values.

    Cables reference devices two ways: ``<FROM>save-ref-id:...`` (matching
    ``<ENGINE><SAVE_REF_ID>``) and ``<FROM_DEVICE_MEM_ADDR>`` (matching
    ``<WORKSPACE><LOGICAL><DEV_ADDR>``). ``SAVE_REF_ID`` is unique per device
    even when multiple devices of the same model share a template ``DEV_ADDR``
    or duplicate device names, so it is indexed directly alongside ``DEV_ADDR``.
    """
    nodes = _nodes(lab)
    targets = values if values is not None else [dev.name for dev in nodes]
    mapped: dict[str, str] = {}
    for dev, target in zip(nodes, targets):
        if dev.save_ref_id:
            mapped[dev.save_ref_id] = target
        if dev.dev_addr:
            mapped.setdefault(dev.dev_addr, target)
        if dev.name:
            mapped.setdefault(dev.name, target)
    for link in _edges(lab):
        cable = link.cable
        if cable is None:
            continue
        for addr, ref in (
            (cable.from_device_addr, cable.from_ref),
            (cable.to_device_addr, cable.to_ref),
        ):
            if addr and addr in mapped and ref:
                mapped.setdefault(ref, mapped[addr])
    return mapped


def _endpoint_names(lab: Lab) -> dict[str, str]:
    """Map every endpoint identifier a cable may use onto a device name."""
    return _endpoint_map(lab)


def _resolve_link_endpoints(link: Link, resolve: dict[str, str]) -> tuple[str, str] | None:
    cable = link.cable
    if cable is None:
        return None
    a = (
        resolve.get(cable.from_ref)
        or resolve.get(cable.from_device_addr)
        or cable.from_ref
        or cable.from_device_addr
    )
    b = (
        resolve.get(cable.to_ref)
        or resolve.get(cable.to_device_addr)
        or cable.to_ref
        or cable.to_device_addr
    )
    if not a and not b:
        return None
    return (a, b)


# --------------------------------------------------------------------------
# Graphviz
# --------------------------------------------------------------------------
def to_graphviz(lab: Lab, *, name: str = "topology") -> str:
    """Render the topology as a Graphviz DOT graph.

    Devices are nodes labelled ``name\\nkind model``; links are edges labelled
    with the two port names. Cable-less links (wireless) are drawn dashed.
    """
    lines: list[str] = [
        f'digraph "{_escape(name)}" {{',
        "  graph [rankdir=LR, splines=true];",
        "  node  [shape=box, style=rounded, fontname=\"Helvetica\"];",
        "  edge  [fontname=\"Helvetica\", fontsize=10];",
    ]
    nodes = _nodes(lab)
    node_keys: list[str] = []
    for i, dev in enumerate(nodes):
        key = f"d{i}"
        node_keys.append(key)
        subtitle = f"{dev.kind} {dev.model}".strip()
        label = f"{_escape(dev.name)}\\n{_escape(subtitle)}" if subtitle else _escape(dev.name)
        lines.append(f'  {key} [label="{label}"];')

    valid_keys = set(node_keys)
    resolve = _endpoint_map(lab, node_keys)
    for link in _edges(lab):
        endpoints = _resolve_link_endpoints(link, resolve)
        if endpoints is None:
            continue
        src, dst = endpoints
        if src not in valid_keys or dst not in valid_keys:
            continue
        ports = link.port_names
        label = " — ".join(ports) if ports else link.type
        style = "dashed" if not link.cable_type else "solid"
        lines.append(
            f'  {src} -> {dst} [dir=none, style={style}, label="{_escape(label)}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# NetBox
# --------------------------------------------------------------------------
def to_netbox(lab: Lab) -> str:
    """Render devices and interfaces as a NetBox-style JSON inventory.

    This is a plain inventory import, not a NetBox REST payload: device names,
    platforms, interface names, MACs and link peers. Cable-less links are
    omitted because NetBox has no peer to record.
    """
    devices: list[dict[str, object]] = []
    for dev in _nodes(lab):
        devices.append(
            {
                "name": dev.name,
                "device_type": {"manufacturer": "Cisco", "model": dev.model},
                "device_role": dev.kind,
                "position": {"x": dev.position[0], "y": dev.position[1]},
                "cluster": dev.cluster_id or None,
                "interfaces": [
                    {
                        "name": f"iface{idx}",
                        "type": port.type,
                        "mac_address": port.mac_address or None,
                        "speed": port.bandwidth or None,
                        "enabled": port.power,
                    }
                    for idx, port in enumerate(dev.ports)
                ],
            }
        )

    resolve = _endpoint_names(lab)
    cables: list[dict[str, object]] = []
    for link in _edges(lab):
        endpoints = _resolve_link_endpoints(link, resolve)
        if endpoints is None:
            continue
        ports = link.port_names
        name_a, name_b = endpoints
        cables.append(
            {
                "type": link.cable_type or link.type,
                "a": {"device": name_a, "port": ports[0] if ports else None},
                "b": {"device": name_b, "port": ports[1] if len(ports) > 1 else None},
                "length": link.cable.length if link.cable else None,
            }
        )

    return json.dumps(
        {
            "format": "pkt-core/netbox-inventory",
            "lab": lab.summary(),
            "devices": devices,
            "cables": cables,
        },
        indent=2,
    ) + "\n"


# --------------------------------------------------------------------------
# containerlab
# --------------------------------------------------------------------------
def to_containerlab(lab: Lab, *, topology_name: str = "pkt") -> str:
    """Render the topology as a containerlab topology YAML stub.

    Containerlab runs containers, so this maps Packet Tracer devices onto
    placeholder kinds rather than inventing images. It is a starting point for
    a lab, not a runnable definition.
    """
    lines: list[str] = [
        f"name: {_yaml_quote(topology_name)}",
        "topology:",
        "  nodes:",
    ]
    used_keys: set[str] = set()
    node_keys: list[str] = []
    for dev in _nodes(lab):
        base = _yaml_key(dev.name)
        node_key = base
        suffix = 2
        while node_key in used_keys:
            node_key = f"{base}-{suffix}"
            suffix += 1
        used_keys.add(node_key)
        node_keys.append(node_key)
        kind = _yaml_key(dev.kind.lower()) or "unknown"
        lines.append(f"    {node_key}:")
        lines.append(f"      kind: {_yaml_quote(kind)}")
        lines.append(f"      # packet-tracer model: {dev.model}")
        if dev.position != (0.0, 0.0):
            lines.append(f"      # canvas position: {dev.position[0]:.0f},{dev.position[1]:.0f}")
    lines.append("  links:")
    resolve = _endpoint_map(lab, node_keys)
    for link in _edges(lab):
        endpoints = _resolve_link_endpoints(link, resolve)
        if endpoints is None:
            continue
        ports = link.port_names
        raw_a, raw_b = endpoints
        key_a = raw_a if raw_a in used_keys else _yaml_key(raw_a)
        key_b = raw_b if raw_b in used_keys else _yaml_key(raw_b)
        ep_a = f"{key_a}:{ports[0]}" if ports else key_a
        ep_b = f"{key_b}:{ports[1]}" if len(ports) > 1 else key_b
        lines.append(f"    - endpoints: [{_yaml_quote(ep_a)}, {_yaml_quote(ep_b)}]")
    return "\n".join(lines) + "\n"


#: Registry used by the CLI.
EXPORTERS: dict[str, Callable[[Lab], str]] = {
    "graphviz": to_graphviz,
    "netbox": to_netbox,
    "containerlab": to_containerlab,
}


def export(lab: Lab, fmt: str) -> str:
    """Render ``lab`` in the named format.

    Raises:
        ExportError: if the format is not registered.
    """
    try:
        fn = EXPORTERS[fmt]
    except KeyError as exc:
        raise ExportError(
            f"unknown export format {fmt!r}; choose from {', '.join(sorted(EXPORTERS))}"
        ) from exc
    return fn(lab)
