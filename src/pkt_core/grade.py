# SPDX-License-Identifier: GPL-3.0-or-later
"""Fast, headless auto-grader for Cisco Packet Tracer ``.pka`` and ``.pkt`` submissions.

Grades a student's saved ``.pka`` activity (or ``.pkt`` topology) offline in
milliseconds without launching Packet Tracer:

1. **Embedded Activity Grading (``.pka``)**:
   A ``.pka`` file embeds three ``<PACKETTRACER5>`` networks:
   ``[0]`` the student's working/saved network, ``[1]`` the initial network,
   and ``[2]`` the solution/answer network, plus the ``<COMPARISONS>`` and
   ``<INITIALSETUP>`` assessment trees.
   :func:`grade_file` / :func:`grade_lab` evaluates the student's working
   network against both the ``<COMPARISONS>`` scoring tree and the answer
   network.

2. **Tamper-Proof Master Reference Grading (``--against master.pka``)**:
   Because a student could edit the embedded ``<ANSWERNETWORK>`` or
   ``<COMPARISONS>`` tree inside their own ``.pka`` before submitting, passing
   ``against=master_lab`` (or ``pkt grade student.pka --against master.pka``)
   evaluates the student's working network against the **instructor's**
   untouched scoring tree and answer network.

3. **``.pkt``-to-``.pkt`` Rubric Grading (``pkt grade student.pkt --against solution.pkt``)**:
   Derives a structured assessment rubric directly from ``solution.pkt``
   (devices, models, power state, cabled links, end-device IPv4/IPv6/gateway/DNS,
   IOS hostname, interfaces, VLANs, switchport modes, static routes, OSPF/BGP/EIGRP
   stanzas, and server DNS/DHCP/AAA services) and grades ``student.pkt`` against
   it item by item.

4. **Batch Parallel Grading (:func:`grade_batch`)**:
   Grades tens or hundreds of submissions concurrently and emits summary tables,
   JSON, or LMS/GitHub Classroom CSV gradebooks.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import os
from pathlib import Path
import re
import time
from typing import Iterable, Mapping, Sequence

from pkt_core.codec.container import decode_bytes
from pkt_core.models.lab import Lab, Network
from pkt_core.models.network import Device
from pkt_core.models.schema import ScoringNode

__all__ = [
    "GradeItem",
    "DeviceScore",
    "GradeReport",
    "grade_lab",
    "grade_bytes",
    "grade_file",
    "grade_batch",
]

_SCAFFOLD_NODES: frozenset[str] = frozenset(
    {
        "Instruction",
        "Resource",
        "ConnectivityTests",
        "CodeTesting",
        "Remote Network",
        "Remote Networks",
        "Encircling Tests",
    }
)

_IFACE_RE = re.compile(r"^interface\s+(\S+)\s*$", re.I)
_IP_ADDR_RE = re.compile(r"^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+secondary)?\s*$", re.I)
_IPV6_ADDR_RE = re.compile(r"^ipv6\s+address\s+(\S+)\s*$", re.I)
_HOSTNAME_RE = re.compile(r"^hostname\s+(\S+)\s*$", re.I)
_DEFAULT_GW_RE = re.compile(r"^ip\s+default-gateway\s+(\S+)\s*$", re.I)
_IP_ROUTE_RE = re.compile(
    r"^ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)(?:\s+\d+)?\s*$",
    re.I,
)
_VLAN_DECL_RE = re.compile(r"^vlan\s+(\d+)\s*$", re.I)
_ROUTER_PROTO_RE = re.compile(r"^router\s+(\S+)(?:\s+(\S+))?\s*$", re.I)
_OSPF_NET_RE = re.compile(
    r"^network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\S+)\s*$",
    re.I,
)
_SW_MODE_RE = re.compile(r"^switchport\s+mode\s+(\S+)\s*$", re.I)
_SW_ACCESS_RE = re.compile(r"^switchport\s+access\s+vlan\s+(\d+)\s*$", re.I)
_SW_NATIVE_RE = re.compile(r"^switchport\s+trunk\s+native\s+vlan\s+(\d+)\s*$", re.I)
_SW_VOICE_RE = re.compile(r"^switchport\s+voice\s+vlan\s+(\d+)\s*$", re.I)
_DESC_RE = re.compile(r"^description\s+(.+)$", re.I)
_CLOCK_RE = re.compile(r"^clock\s+rate\s+(\d+)\s*$", re.I)
_ENCAP_DOT1Q_RE = re.compile(r"^encapsulation\s+dot1Q\s+(\d+)(?:\s+native)?\s*$", re.I)
_ACCESS_GROUP_RE = re.compile(r"^ip\s+access-group\s+(\S+)\s+(in|out)\s*$", re.I)
_SSH_VER_RE = re.compile(r"^ip\s+ssh\s+version\s+(\S+)\s*$", re.I)
_ROUTER_ID_RE = re.compile(r"^(?:bgp\s+)?router-id\s+(\S+)\s*$", re.I)
_OSPF_AUTOCOST_RE = re.compile(r"^auto-cost\s+reference-bandwidth\s+(\S+)\s*$", re.I)
_VTP_DOMAIN_RE = re.compile(r"^vtp\s+domain\s+(\S+)\s*$", re.I)

#: Host kinds whose NICs Packet Tracer names without a slot (``FastEthernet0``).
_END_DEVICE_KINDS: frozenset[str] = frozenset(
    {"pc", "laptop", "server", "tabletpc", "pda", "printer"}
)


# --------------------------------------------------------------------------- #
# data models
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class GradeItem:
    """One graded assessment check on a device or link."""

    device: str
    category: str
    item: str
    path: str
    expected: str
    actual: str
    passed: bool
    points_earned: int
    points_possible: int
    feedback: str = ""

    def as_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "device": self.device,
            "category": self.category,
            "item": self.item,
            "path": self.path,
            "expected": self.expected,
            "actual": self.actual,
            "passed": self.passed,
            "points_earned": self.points_earned,
            "points_possible": self.points_possible,
        }
        if self.feedback:
            d["feedback"] = self.feedback
        return d


@dataclass(frozen=True)
class DeviceScore:
    """Aggregated score for a single device."""

    device: str
    model: str
    points_earned: int
    points_possible: int
    items_passed: int
    items_total: int

    @property
    def percentage(self) -> float:
        if self.points_possible <= 0:
            return 100.0
        return round((self.points_earned / self.points_possible) * 100.0, 2)

    def as_dict(self) -> dict[str, object]:
        return {
            "device": self.device,
            "model": self.model,
            "points_earned": self.points_earned,
            "points_possible": self.points_possible,
            "items_passed": self.items_passed,
            "items_total": self.items_total,
            "percentage": self.percentage,
        }


@dataclass(frozen=True)
class GradeReport:
    """Complete grading report for one ``.pka`` or ``.pkt`` submission."""

    target: str
    mode: str
    points_earned: int
    points_possible: int
    items: tuple[GradeItem, ...]
    devices: tuple[DeviceScore, ...]
    pass_threshold: float = 100.0
    feedback: str = ""
    elapsed_ms: float = 0.0

    @property
    def percentage(self) -> float:
        if self.points_possible <= 0:
            return 100.0
        return round((self.points_earned / self.points_possible) * 100.0, 2)

    @property
    def passed(self) -> bool:
        return self.percentage + 1e-9 >= self.pass_threshold

    @property
    def items_passed(self) -> int:
        return sum(1 for it in self.items if it.passed)

    @property
    def items_failed(self) -> int:
        return sum(1 for it in self.items if not it.passed)

    @property
    def failed_items(self) -> tuple[GradeItem, ...]:
        return tuple(it for it in self.items if not it.passed)

    def as_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "mode": self.mode,
            "passed": self.passed,
            "percentage": self.percentage,
            "pass_threshold": self.pass_threshold,
            "points_earned": self.points_earned,
            "points_possible": self.points_possible,
            "items_passed": self.items_passed,
            "items_total": len(self.items),
            "feedback": self.feedback,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "devices": [d.as_dict() for d in self.devices],
            "items": [it.as_dict() for it in self.items],
        }

    def summary(self, *, show_passed: bool = False) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [
            f"{self.target}: {status}  {self.percentage:.1f}% "
            f"({self.points_earned}/{self.points_possible} pts, "
            f"{self.items_passed}/{len(self.items)} items, {self.elapsed_ms:.1f} ms)",
        ]
        if self.devices:
            lines.append("  devices:")
            for d in self.devices:
                lines.append(
                    f"    {d.device:<22s} ({d.model:<12s}) "
                    f"{d.points_earned:>3d}/{d.points_possible:<3d} pts  ({d.percentage:5.1f}%)"
                )
        shown = self.items if show_passed else self.failed_items
        if shown:
            header = "  assessment items:" if show_passed else "  failed items:"
            lines.append(header)
            for it in shown:
                mark = "ok" if it.passed else "MISS"
                line = (
                    f"    [{mark:<4s}] {it.device:<18s} {it.item:<36s} "
                    f"expected={it.expected!r} actual={it.actual!r} "
                    f"({it.points_earned}/{it.points_possible} pt)"
                )
                if not it.passed and it.feedback:
                    line += f" -- {it.feedback}"
                lines.append(line)
        if self.feedback:
            lines.append(f"  feedback: {self.feedback}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# fast single-pass device state extraction
# --------------------------------------------------------------------------- #
@dataclass
class _IfaceState:
    name: str
    ip: str = ""
    mask: str = ""
    ipv6: str = ""
    shutdown: bool = True
    has_shutdown_cmd: bool = False
    description: str = ""
    switchport_mode: str = ""
    access_vlan: str = "1"
    native_vlan: str = "1"
    voice_vlan: str = "0"
    encap_dot1q: str = ""
    clock_rate: str = ""
    access_group_in: str = ""
    access_group_out: str = ""
    ospf_process: str = ""
    ospf_area: str = ""
    dhcp_relay: str = ""


@dataclass
class _DeviceState:
    name: str
    model: str
    kind: str
    powered: bool
    hostname: str
    default_gateway: str
    dns_server: str
    enable_secret: bool
    ip_routing: bool
    ipv6_unicast_routing: bool
    interfaces: dict[str, _IfaceState]
    vlans: dict[str, str]
    static_routes: set[tuple[str, str, str]]
    ospf_networks: dict[str, set[tuple[str, str, str]]]
    peers: dict[str, tuple[str, str, str]]
    dhcp_pools: dict[str, tuple[str, str, str]]
    dns_records: dict[str, str]
    aaa_clients: dict[str, str]
    custom_vars: dict[str, str]
    flat_props: dict[str, str]


def _canonical_port_name(raw: str) -> str:
    s = raw.strip()
    for short, full in (
        ("Gig0/", "GigabitEthernet0/"),
        ("Gi0/", "GigabitEthernet0/"),
        ("Fa0/", "FastEthernet0/"),
        ("Eth0/", "Ethernet0/"),
        ("Se0/", "Serial0/"),
        ("Lo", "Loopback"),
        ("Vl", "Vlan"),
    ):
        if s.startswith(short) and not s.startswith(full):
            return full + s[len(short) :]
    return s


def _declared_interfaces(rc_lines: Sequence[bytes]) -> set[str]:
    """Canonical names of the ``interface`` stanzas in a running config."""
    names: set[str] = set()
    for raw_line in rc_lines:
        if raw_line.startswith(b" "):
            continue
        m = _IFACE_RE.match(raw_line.decode("utf-8", "replace").strip())
        if m:
            names.add(_canonical_port_name(m.group(1)))
    return names


def _extract_network_state(net: Network | None) -> dict[str, _DeviceState]:
    if net is None:
        return {}
    devices = net.devices

    # Map endpoint IDs (save_ref_id and dev_addr) -> device name
    ref_to_name: dict[str, str] = {}
    for d in devices:
        if d.save_ref_id:
            ref_to_name[d.save_ref_id] = d.name
        if d.dev_addr:
            ref_to_name[d.dev_addr] = d.name

    # Map device_name -> {local_port: (peer_device_name, peer_port, cable_type)}
    peers_by_dev: dict[str, dict[str, tuple[str, str, str]]] = {d.name: {} for d in devices}
    for link in net.links:
        cab = link.cable
        if cab is None:
            continue
        dev_a = ref_to_name.get(cab.from_ref) or ref_to_name.get(cab.from_device_addr, "")
        dev_b = ref_to_name.get(cab.to_ref) or ref_to_name.get(cab.to_device_addr, "")
        ports = cab.ports
        port_a = ports[0] if len(ports) > 0 else ""
        port_b = ports[1] if len(ports) > 1 else ""
        if dev_a and dev_b and port_a and port_b:
            ca = _canonical_port_name(port_a)
            cb = _canonical_port_name(port_b)
            peers_by_dev.setdefault(dev_a, {})[ca] = (dev_b, cb, cab.cable_type)
            peers_by_dev.setdefault(dev_b, {})[cb] = (dev_a, ca, cab.cable_type)

    out: dict[str, _DeviceState] = {}
    for d in devices:
        out[d.name] = _extract_device_state(d, peers_by_dev.get(d.name, {}))
    return out


def _extract_device_state(
    dev: Device,
    peers: Mapping[str, tuple[str, str, str]],
) -> _DeviceState:
    ifaces: dict[str, _IfaceState] = {}
    vlans: dict[str, str] = {"1": "default"}
    static_routes: set[tuple[str, str, str]] = set()
    ospf_networks: dict[str, set[tuple[str, str, str]]] = {}
    dhcp_pools: dict[str, tuple[str, str, str]] = {}
    dns_records: dict[str, str] = {}
    aaa_clients: dict[str, str] = {}
    custom_vars: dict[str, str] = {}

    hostname = dev.name
    eng_gw = ""
    has_eng_gw_tag = False
    if dev.engine is not None:
        gw_el = dev.engine.find("GATEWAY")
        if gw_el is not None:
            has_eng_gw_tag = True
            eng_gw = gw_el.text.strip()
    default_gw = eng_gw if has_eng_gw_tag else dev.gateway
    dns_srv = ""
    enable_secret = False
    ip_routing = dev.kind.lower() in ("router", "multilayerswitch")
    ipv6_routing = False
    svc_pwd_enc = False
    aaa_new_model = False
    ntp_auth = False
    ntp_cal = False
    ssh_ver = ""
    vtp_domain = ""
    stp_rstp = False
    ospf_router_ids: dict[str, str] = {}
    ospf_auto_costs: dict[str, str] = {}
    bgp_as = ""
    bgp_router_id = ""
    bgp_log_nbr = False
    bgp_no_sync = False

    # 1. Hardware / end-device XML ports.  A <PORT> carries no interface name,
    #    so one is guessed from its media type, and a guess must never invent
    #    an interface.  End devices follow PT's host naming (FastEthernet0).
    #    Elsewhere a guess only counts if the running config declares it, and
    #    switch ports are not guessed at all: the config lists every one.
    kind = dev.kind.lower()
    is_end_device = kind in _END_DEVICE_KINDS
    declared: set[str] = (
        set() if kind in ("switch", "multilayerswitch") else _declared_interfaces(dev.running_config)
    )
    slot = "" if is_end_device else "0/"
    fa_idx = 0
    gi_idx = 0
    host_nic: _IfaceState | None = None
    for p in dev.ports:
        p_type = p.type
        guess_name = ""
        if "FastEthernet" in p_type:
            guess_name = f"FastEthernet{slot}{fa_idx}"
            fa_idx += 1
        elif "GigabitEthernet" in p_type:
            guess_name = f"GigabitEthernet{slot}{gi_idx}"
            gi_idx += 1
        if not is_end_device and guess_name not in declared:
            guess_name = ""
        cfg = p.config
        if guess_name and cfg.ip_address and cfg.ip_address != "0.0.0.0":
            st = ifaces.setdefault(guess_name, _IfaceState(name=guess_name))
            st.ip = cfg.ip_address
            st.mask = cfg.subnet_mask
            st.shutdown = not p.power
            if host_nic is None:
                host_nic = st
        if not has_eng_gw_tag and cfg.gateway and cfg.gateway != "0.0.0.0" and not default_gw:
            default_gw = cfg.gateway
        if cfg.dns and cfg.dns != "0.0.0.0" and not dns_srv:
            dns_srv = cfg.dns
    # Also alias FastEthernet0 for single-NIC hosts, but only where it exists
    if is_end_device and host_nic is not None and fa_idx > 0:
        ifaces.setdefault("FastEthernet0", host_nic)

    # 2. Running-config single-pass parser
    rc_lines = dev.running_config
    if rc_lines:
        cur_iface: _IfaceState | None = None
        cur_vlan: str | None = None
        cur_router_proto: str = ""
        cur_router_id: str = ""
        cur_dhcp_pool: str = ""
        dhcp_net = ""
        dhcp_mask = ""
        dhcp_gw = ""

        for raw_line in rc_lines:
            line = raw_line.decode("utf-8", "replace")
            s = line.strip()
            if not s or s == "!":
                continue

            if not line.startswith(" "):
                if cur_dhcp_pool and dhcp_net:
                    dhcp_pools[cur_dhcp_pool] = (dhcp_net, dhcp_mask, dhcp_gw)
                cur_iface = None
                cur_vlan = None
                cur_router_proto = ""
                cur_dhcp_pool = ""

                low_s = s.lower()
                if low_s == "end":
                    break
                m = _IFACE_RE.match(s)
                if m:
                    iname = _canonical_port_name(m.group(1))
                    cur_iface = ifaces.setdefault(iname, _IfaceState(name=iname))
                    continue
                m = _HOSTNAME_RE.match(s)
                if m:
                    hostname = m.group(1)
                    continue
                m = _DEFAULT_GW_RE.match(s)
                if m:
                    default_gw = m.group(1)
                    continue
                m = _IP_ROUTE_RE.match(s)
                if m:
                    static_routes.add((m.group(1), m.group(2), m.group(3)))
                    continue
                m = _VLAN_DECL_RE.match(s)
                if m:
                    cur_vlan = m.group(1)
                    vlans.setdefault(cur_vlan, f"VLAN{cur_vlan.zfill(4)}")
                    continue
                m = _ROUTER_PROTO_RE.match(s)
                if m:
                    cur_router_proto = m.group(1).lower()
                    cur_router_id = m.group(2) or "1"
                    if cur_router_proto == "bgp":
                        bgp_as = cur_router_id
                    continue
                if low_s.startswith("ip dhcp pool "):
                    cur_dhcp_pool = s.split(None, 3)[3].strip()
                    dhcp_net = dhcp_mask = dhcp_gw = ""
                    continue
                if low_s.startswith(("enable secret ", "enable password ")):
                    enable_secret = True
                    continue
                if low_s == "service password-encryption":
                    svc_pwd_enc = True
                    continue
                if low_s == "no service password-encryption":
                    svc_pwd_enc = False
                    continue
                if low_s == "aaa new-model":
                    aaa_new_model = True
                    continue
                if low_s == "no aaa new-model":
                    aaa_new_model = False
                    continue
                if low_s == "ntp authenticate":
                    ntp_auth = True
                    continue
                if low_s == "ntp update-calendar":
                    ntp_cal = True
                    continue
                m = _SSH_VER_RE.match(s)
                if m:
                    ssh_ver = m.group(1)
                    continue
                m = _VTP_DOMAIN_RE.match(s)
                if m:
                    vtp_domain = m.group(1)
                    continue
                if low_s == "spanning-tree mode rapid-pvst":
                    stp_rstp = True
                    continue
                if low_s.startswith("spanning-tree mode "):
                    stp_rstp = False
                    continue
                if low_s == "ip routing":
                    ip_routing = True
                    continue
                if low_s == "no ip routing":
                    ip_routing = False
                    continue
                if low_s == "ipv6 unicast-routing":
                    ipv6_routing = True
                    continue
                continue

            # Indented subcommands
            if cur_iface is not None:
                if s.lower() == "shutdown":
                    cur_iface.shutdown = True
                    cur_iface.has_shutdown_cmd = True
                    continue
                if s.lower() == "no shutdown":
                    cur_iface.shutdown = False
                    cur_iface.has_shutdown_cmd = True
                    continue
                m = _IP_ADDR_RE.match(s)
                if m:
                    cur_iface.ip = m.group(1)
                    cur_iface.mask = m.group(2)
                    continue
                m = _IPV6_ADDR_RE.match(s)
                if m:
                    addr = m.group(1)
                    if not addr.upper().startswith("FE80:"):
                        cur_iface.ipv6 = addr
                    continue
                m = _SW_MODE_RE.match(s)
                if m:
                    cur_iface.switchport_mode = m.group(1).lower()
                    continue
                m = _SW_ACCESS_RE.match(s)
                if m:
                    cur_iface.access_vlan = m.group(1)
                    continue
                m = _SW_NATIVE_RE.match(s)
                if m:
                    cur_iface.native_vlan = m.group(1)
                    continue
                m = _SW_VOICE_RE.match(s)
                if m:
                    cur_iface.voice_vlan = m.group(1)
                    continue
                m = _DESC_RE.match(s)
                if m:
                    cur_iface.description = m.group(1).strip()
                    continue
                m = _CLOCK_RE.match(s)
                if m:
                    cur_iface.clock_rate = m.group(1)
                    continue
                m = _ENCAP_DOT1Q_RE.match(s)
                if m:
                    cur_iface.encap_dot1q = m.group(1)
                    continue
                m = _ACCESS_GROUP_RE.match(s)
                if m:
                    if m.group(2).lower() == "in":
                        cur_iface.access_group_in = m.group(1)
                    else:
                        cur_iface.access_group_out = m.group(1)
                    continue
                if s.lower().startswith("ip helper-address "):
                    cur_iface.dhcp_relay = s.split()[-1]
                    continue
                if s.lower().startswith("ip ospf "):
                    parts = s.split()
                    if len(parts) >= 5 and parts[3].lower() == "area":
                        cur_iface.ospf_process = parts[2]
                        cur_iface.ospf_area = parts[4]
                    continue
            elif cur_vlan is not None:
                if s.lower().startswith("name "):
                    vlans[cur_vlan] = s[5:].strip()
            elif cur_router_proto == "ospf":
                m = _OSPF_NET_RE.match(s)
                if m:
                    ospf_networks.setdefault(cur_router_id, set()).add(
                        (m.group(1), m.group(2), m.group(3))
                    )
                    continue
                m = _ROUTER_ID_RE.match(s)
                if m:
                    ospf_router_ids[cur_router_id] = m.group(1)
                    continue
                m = _OSPF_AUTOCOST_RE.match(s)
                if m:
                    ospf_auto_costs[cur_router_id] = m.group(1)
            elif cur_router_proto == "bgp":
                low_s = s.lower()
                m = _ROUTER_ID_RE.match(s)
                if m:
                    bgp_router_id = m.group(1)
                elif low_s == "bgp log-neighbor-changes":
                    bgp_log_nbr = True
                elif low_s == "no bgp log-neighbor-changes":
                    bgp_log_nbr = False
                elif low_s == "no synchronization":
                    bgp_no_sync = True
                elif low_s == "synchronization":
                    bgp_no_sync = False
            elif cur_dhcp_pool:
                low = s.lower()
                if low.startswith("network "):
                    parts = s.split()
                    if len(parts) >= 3:
                        dhcp_net, dhcp_mask = parts[1], parts[2]
                elif low.startswith("default-router "):
                    dhcp_gw = s.split()[1]

        if cur_dhcp_pool and dhcp_net:
            dhcp_pools[cur_dhcp_pool] = (dhcp_net, dhcp_mask, dhcp_gw)

    # PT saves `show running-config` output, which prints `shutdown` but never
    # `no shutdown`: a declared interface is up unless shut down (or, for a Vlan
    # SVI, configured with an IP address and no `shutdown`).
    # Every interface on these kinds is config-declared (see the guessing above).
    if kind in ("router", "switch", "multilayerswitch"):
        for st in ifaces.values():
            if not st.has_shutdown_cmd and (not st.name.lower().startswith("vlan") or st.ip):
                st.shutdown = False

    # 3. Server services (DHCP, DNS, AAA)
    srv = dev.services
    if srv is not None:
        for pool in srv.dhcp_pools:
            if pool.name and pool.network:
                dhcp_pools[pool.name] = (pool.network, pool.mask, pool.default_router)
        for rec in srv.dns_records:
            if rec.name and rec.ip_address:
                dns_records[rec.name] = rec.ip_address
        for cl in srv.aaa_clients:
            if cl.host_ip:
                aaa_clients[cl.host_ip] = cl.server_type

    # 4. Flat property lookup index (matches Packet Tracer <COMPARISONS> node paths/IDs)
    flat: dict[str, str] = {
        "Device Model": dev.model,
        "Host Name": hostname,
        "Power": "1" if dev.powered else "0",
        "Default Gateway": default_gw,
        "DNS Server": dns_srv or "0.0.0.0",
        "Routes/IP Routing": "1" if ip_routing else "0",
        "Routesv6/Ipv6 Unicast Routing": "1" if ipv6_routing else "0",
        "Service Password Encryption": "1" if svc_pwd_enc else "0",
        "AAA/New-model": "1" if aaa_new_model else "0",
        "NTP/NTP Authenticate": "1" if ntp_auth else "0",
        "NTP/Update Calendar": "1" if ntp_cal else "0",
        "STP/RSTP": "1" if stp_rstp else "0",
    }
    if ssh_ver:
        flat["SSH Server/SSH Server Version"] = ssh_ver
    if vtp_domain:
        flat["VTP/Domain Name"] = vtp_domain
    for pid, rid in ospf_router_ids.items():
        flat[f"OSPF/{pid}/Router ID"] = rid
    for pid, ac in ospf_auto_costs.items():
        flat[f"OSPF/{pid}/Auto Cost"] = ac
    if bgp_as:
        flat["BGP/Autonomous System"] = bgp_as
        if bgp_router_id:
            flat["BGP/Router ID"] = bgp_router_id
        flat["BGP/Log Neighbor Changes"] = "1" if bgp_log_nbr else "0"
        flat["BGP/Synchronization"] = "0" if bgp_no_sync else "1"
    if is_end_device and "FastEthernet0" in ifaces:
        flat["Ports/FastEthernet0/Default Gateway"] = default_gw

    primary_ip = ""
    primary_mask = ""
    any_port_up = False
    for iname, st in ifaces.items():
        up_str = "0" if st.shutdown else "1"
        if not st.shutdown:
            any_port_up = True
        if st.ip and not primary_ip:
            primary_ip = st.ip
            primary_mask = st.mask
        prefix = f"Ports/{iname}"
        flat[f"{prefix}/IP Address"] = st.ip
        flat[f"{prefix}/Subnet Mask"] = st.mask
        flat[f"{prefix}/Port Up"] = up_str
        flat[f"{prefix}/Power"] = up_str
        flat[f"{prefix}/Description"] = st.description
        flat[f"{prefix}/Access VLAN"] = st.access_vlan
        flat[f"{prefix}/Native VLAN"] = st.native_vlan
        flat[f"{prefix}/Voice Vlan"] = st.voice_vlan
        if st.switchport_mode:
            flat[f"{prefix}/Port Mode"] = "1" if st.switchport_mode == "trunk" else "0"
            flat[f"{prefix}/Dynamic Mode"] = {"trunk": "2", "access": "3"}.get(
                st.switchport_mode, "1"
            )
        elif kind in ("switch", "multilayerswitch") and "ethernet" in iname.lower():
            flat[f"{prefix}/Dynamic Mode"] = "1"
        if st.clock_rate:
            flat[f"{prefix}/Clock Rate"] = st.clock_rate
        if st.access_group_in:
            flat[f"{prefix}/Access-group In"] = st.access_group_in
        if st.access_group_out:
            flat[f"{prefix}/Access-group Out"] = st.access_group_out

    for p_port, (peer_dev, peer_port, _ctype) in peers.items():
        link_prefix = f"Ports/{p_port}/Link to {peer_dev}"
        flat[f"{link_prefix}/Connects to {peer_port}"] = f"Connects to {peer_port}"

    for vid, vname in vlans.items():
        flat[f"VLANS/{vid}"] = vid
        flat[f"VLANS/{vid}/VLAN Name"] = vname

    if primary_ip:
        flat["IP Address"] = primary_ip
        flat["Subnet Mask"] = primary_mask
    flat["Port Up"] = "1" if any_port_up else "0"

    return _DeviceState(
        name=dev.name,
        model=dev.model,
        kind=dev.kind,
        powered=dev.powered,
        hostname=hostname,
        default_gateway=default_gw,
        dns_server=dns_srv,
        enable_secret=enable_secret,
        ip_routing=ip_routing,
        ipv6_unicast_routing=ipv6_routing,
        interfaces=ifaces,
        vlans=vlans,
        static_routes=static_routes,
        ospf_networks=ospf_networks,
        peers=dict(peers),
        dhcp_pools=dhcp_pools,
        dns_records=dns_records,
        aaa_clients=aaa_clients,
        custom_vars=custom_vars,
        flat_props=flat,
    )


# --------------------------------------------------------------------------- #
# rubric & <COMPARISONS> evaluation
# --------------------------------------------------------------------------- #
def _category_for_path(rel_path: str) -> str:
    if rel_path.startswith("Ports/"):
        if "/Link to " in rel_path:
            return "Physical"
        if any(k in rel_path for k in ("VLAN", "Port Mode", "Dynamic Mode", "Trunk", "PortFast", "Bpdu")):
            return "Switching"
        return "Ip"
    if rel_path.startswith(("VLANS", "STP", "VTP", "EtherChannel")):
        return "Switching"
    if rel_path.startswith(("OSPF", "Routes", "BGP", "EIGRP", "RIP")):
        return "Routing"
    if rel_path.startswith(("ACL", "ACLV6", "IKE")):
        return "Acl"
    return "Other"


def _collect_Explicit_tree_checks(
    comp_roots: Sequence[ScoringNode],
    init_roots: Sequence[ScoringNode],
) -> tuple[list[tuple[str, str, str, str, int, str, str]], bool]:
    """Return ``(checks, has_explicit_ct)`` from a ``<COMPARISONS>`` tree.

    Each check tuple is
    ``(device_name, rel_path, label, expected_val, points, feedback, category)``.

    Selects nodes that either:
    1. Carry an explicit ``checkType > 0`` on a leaf node with points/nodeValue, or
    2. Differ in ``nodeValue`` between ``<COMPARISONS>`` and ``<INITIALSETUP>``
       (or were overridden by ``tools/scoring.py``).
    """
    init_values: dict[tuple[str, str], str] = {}

    def _walk_init(node: ScoringNode, dev_name: str, rel: str) -> None:
        key = node.node_id or node.name
        next_rel = f"{rel}/{key}" if rel else key
        init_values[(dev_name, next_rel)] = node.node_value
        for ch in node.children:
            _walk_init(ch, dev_name, next_rel)

    for root in init_roots:
        for dev_node in root.children:
            dname = dev_node.node_id or dev_node.name
            if dname in _SCAFFOLD_NODES:
                continue
            for ch in dev_node.children:
                _walk_init(ch, dname, "")

    explicit_ct: list[tuple[str, str, str, str, int, str, str]] = []
    diff_from_init: list[tuple[str, str, str, str, int, str, str]] = []

    def _walk_comp(node: ScoringNode, dev_name: str, rel: str) -> None:
        key = node.node_id or node.name
        next_rel = f"{rel}/{key}" if rel else key
        children = node.children
        nv = node.node_value
        pts = node.points_value
        ct = node.check_type
        fb = node.incorrect_feedback

        if not children:
            cat = node.components.strip() or _category_for_path(next_rel)
            if ct > 0 and (pts > 0 or nv):
                explicit_ct.append(
                    (dev_name, next_rel, node.name or key, nv, max(pts, 1), fb, cat)
                )
            elif pts > 0 and nv:
                init_nv = init_values.get((dev_name, next_rel))
                if init_nv is not None and init_nv != nv and not next_rel.endswith("IPv6 NAT Prefix"):
                    diff_from_init.append(
                        (dev_name, next_rel, node.name or key, nv, pts, fb, cat)
                    )
        for ch in children:
            _walk_comp(ch, dev_name, next_rel)

    for root in comp_roots:
        for dev_node in root.children:
            dname = dev_node.node_id or dev_node.name
            if dname in _SCAFFOLD_NODES:
                continue
            for ch in dev_node.children:
                _walk_comp(ch, dname, "")

    if explicit_ct:
        return explicit_ct, True
    return diff_from_init, False


def _derive_rubric_checks(
    answer_states: Mapping[str, _DeviceState],
    initial_states: Mapping[str, _DeviceState] | None = None,
) -> list[tuple[str, str, str, str, str, int]]:
    """Derive ``[(device_name, category, item_label, path_key, expected_val, points), ...]``
    from an answer network's device states.

    When ``initial_states`` is provided (e.g. from block 1 of a ``.pka``), items
    that were already identical in the initial starter network are excluded unless
    no difference exists (in which case all authored configuration items on the
    answer network are graded).
    """
    all_checks: list[tuple[str, str, str, str, str, int]] = []
    delta_checks: list[tuple[str, str, str, str, str, int]] = []
    init_map = initial_states or {}

    for dname, ans in answer_states.items():
        init = init_map.get(dname)

        def _add(cat: str, label: str, path_key: str, expected: str, init_val: str | None, pts: int = 1) -> None:
            entry = (dname, cat, label, path_key, expected, pts)
            all_checks.append(entry)
            if init is None or init_val != expected:
                delta_checks.append(entry)

        # 1. Device presence & model
        _add("Physical", "Device Model", "Device Model", ans.model, init.model if init else None)

        # 2. Power state
        if ans.powered:
            _add(
                "Physical",
                "Power",
                "Power",
                "1",
                ("1" if init.powered else "0") if init else None,
            )

        # 3. Hostname
        if ans.hostname:
            _add(
                "Other",
                "Host Name",
                "Host Name",
                ans.hostname,
                init.hostname if init else None,
            )

        # 4. Default Gateway (end devices & switches)
        if ans.default_gateway and ans.default_gateway != "0.0.0.0":
            _add(
                "Ip",
                "Default Gateway",
                "Default Gateway",
                ans.default_gateway,
                init.default_gateway if init else None,
            )

        # 5. DNS Server (end devices)
        if ans.dns_server and ans.dns_server != "0.0.0.0":
            _add(
                "Ip",
                "DNS Server",
                "DNS Server",
                ans.dns_server,
                init.dns_server if init else None,
            )

        # 6. Interfaces (IP, mask, admin status, switchport mode/VLANs, clock rate, ACLs)
        for iname, st in sorted(ans.interfaces.items()):
            init_if = init.interfaces.get(iname) if init else None
            prefix = f"Ports/{iname}"
            if st.ip and st.ip != "0.0.0.0":
                _add(
                    "Ip",
                    f"{iname} IP Address",
                    f"{prefix}/IP Address",
                    st.ip,
                    init_if.ip if init_if else None,
                )
                if st.mask:
                    _add(
                        "Ip",
                        f"{iname} Subnet Mask",
                        f"{prefix}/Subnet Mask",
                        st.mask,
                        init_if.mask if init_if else None,
                    )
            if not st.shutdown and (st.ip or st.switchport_mode or iname in ans.peers):
                init_up = ("0" if init_if.shutdown else "1") if init_if else None
                _add("Ip", f"{iname} Port Up", f"{prefix}/Port Up", "1", init_up)
            if st.switchport_mode:
                mode_code = "1" if st.switchport_mode == "trunk" else "0"
                init_mode = (
                    ("1" if init_if.switchport_mode == "trunk" else "0")
                    if (init_if and init_if.switchport_mode)
                    else None
                )
                _add(
                    "Switching",
                    f"{iname} Switchport Mode ({st.switchport_mode})",
                    f"{prefix}/Port Mode",
                    mode_code,
                    init_mode,
                )
            if st.access_vlan != "1":
                _add(
                    "Switching",
                    f"{iname} Access VLAN",
                    f"{prefix}/Access VLAN",
                    st.access_vlan,
                    init_if.access_vlan if init_if else None,
                )
            if st.native_vlan != "1":
                _add(
                    "Switching",
                    f"{iname} Native VLAN",
                    f"{prefix}/Native VLAN",
                    st.native_vlan,
                    init_if.native_vlan if init_if else None,
                )
            if st.clock_rate:
                _add(
                    "Physical",
                    f"{iname} Clock Rate",
                    f"{prefix}/Clock Rate",
                    st.clock_rate,
                    init_if.clock_rate if init_if else None,
                )
            if st.access_group_in:
                _add(
                    "Acl",
                    f"{iname} ACL In",
                    f"{prefix}/Access-group In",
                    st.access_group_in,
                    init_if.access_group_in if init_if else None,
                )
            if st.access_group_out:
                _add(
                    "Acl",
                    f"{iname} ACL Out",
                    f"{prefix}/Access-group Out",
                    st.access_group_out,
                    init_if.access_group_out if init_if else None,
                )

        # 7. Cabled links
        for p_port, (peer_dev, peer_port, _ctype) in sorted(ans.peers.items()):
            link_key = f"Ports/{p_port}/Link to {peer_dev}/Connects to {peer_port}"
            expected_link = f"Connects to {peer_port}"
            init_peer = init.peers.get(p_port) if init else None
            init_link = (
                f"Connects to {init_peer[1]}"
                if (init_peer and init_peer[0] == peer_dev)
                else None
            )
            _add(
                "Physical",
                f"{p_port} Link to {peer_dev}:{peer_port}",
                link_key,
                expected_link,
                init_link,
            )

        # 8. Non-default VLANs
        for vid, vname in sorted(ans.vlans.items()):
            if vid in ("1", "1002", "1003", "1004", "1005"):
                continue
            init_vname = init.vlans.get(vid) if init else None
            _add("Switching", f"VLAN {vid}", f"VLANS/{vid}", vid, vid if init_vname else None)
            _add(
                "Switching",
                f"VLAN {vid} Name",
                f"VLANS/{vid}/VLAN Name",
                vname,
                init_vname,
            )

        # 9. Static routes
        for net_addr, mask, nh in sorted(ans.static_routes):
            rk = f"Routes/Static/{net_addr}/{mask}/{nh}"
            has_init = (init is not None) and ((net_addr, mask, nh) in init.static_routes)
            _add(
                "Routing",
                f"Static Route {net_addr}/{mask} via {nh}",
                rk,
                nh,
                nh if has_init else None,
            )

        # 10. OSPF network statements
        for pid, nets in sorted(ans.ospf_networks.items()):
            init_nets = init.ospf_networks.get(pid, set()) if init else set()
            for net_addr, wild, area in sorted(nets):
                ok = f"OSPF/{pid}/Network/{net_addr}/{wild}/{area}"
                _add(
                    "Routing",
                    f"OSPF {pid} network {net_addr} {wild} area {area}",
                    ok,
                    area,
                    area if (net_addr, wild, area) in init_nets else None,
                )

        # 11. DHCP pools, DNS records, AAA clients
        for pname, (pnet, pmask, pgw) in sorted(ans.dhcp_pools.items()):
            dk = f"DHCP/Pools/{pname}"
            val = f"{pnet}/{pmask} gw={pgw}"
            init_p = init.dhcp_pools.get(pname) if init else None
            init_val = f"{init_p[0]}/{init_p[1]} gw={init_p[2]}" if init_p else None
            _add("Other", f"DHCP Pool {pname}", dk, val, init_val)

        for rname, rip in sorted(ans.dns_records.items()):
            rk = f"DNS/Records/{rname}"
            init_rip = init.dns_records.get(rname) if init else None
            _add("Other", f"DNS Record {rname}", rk, rip, init_rip)

        for cip, stype in sorted(ans.aaa_clients.items()):
            ak = f"AAA/Clients/{cip}"
            init_stype = init.aaa_clients.get(cip) if init else None
            _add("Other", f"AAA Client {cip}", ak, stype or "Radius", init_stype)

    return delta_checks if delta_checks else all_checks


def _lookup_actual_value(state: _DeviceState | None, path_key: str) -> str:
    if state is None:
        return "<missing device>"
    if path_key in state.flat_props:
        return state.flat_props[path_key]
    if path_key.startswith("Routes/Static/"):
        parts = path_key.split("/")
        if len(parts) == 5:
            net_addr, mask, nh = parts[2], parts[3], parts[4]
            if (net_addr, mask, nh) in state.static_routes:
                return nh
            for s_net, s_mask, s_nh in state.static_routes:
                if s_net == net_addr and s_mask == mask:
                    return s_nh
        return ""
    if path_key.startswith("OSPF/"):
        parts = path_key.split("/")
        if len(parts) == 6 and parts[2] == "Network":
            pid, net_addr, wild, area = parts[1], parts[3], parts[4], parts[5]
            for p_nets in (state.ospf_networks.get(pid, set()), *[v for v in state.ospf_networks.values()]):
                if (net_addr, wild, area) in p_nets:
                    return area
        return ""
    if path_key.startswith("DHCP/Pools/"):
        pname = path_key[len("DHCP/Pools/") :]
        if pname in state.dhcp_pools:
            pnet, pmask, pgw = state.dhcp_pools[pname]
            return f"{pnet}/{pmask} gw={pgw}"
        return ""
    if path_key.startswith("DNS/Records/"):
        rname = path_key[len("DNS/Records/") :]
        return state.dns_records.get(rname, "")
    if path_key.startswith("AAA/Clients/"):
        cip = path_key[len("AAA/Clients/") :]
        return state.aaa_clients.get(cip, "")
    # No leaf-key fallback: a top-level key (no "/") was already looked up above,
    # and a nested one the student lacks (e.g. "Ports/Gi0/1.10/Subnet Mask") must
    # stay missing -- its leaf ("Subnet Mask") would read another interface.
    # tools/scoring.py trees only use top-level keys or full "Ports/<iface>/..." paths.
    return ""


# --------------------------------------------------------------------------- #
# public grading entry points
# --------------------------------------------------------------------------- #
def grade_lab(
    submission: Lab,
    *,
    against: Lab | None = None,
    target_name: str = "<memory>",
    pass_threshold: float = 100.0,
    categories: Iterable[str] | None = None,
) -> GradeReport:
    """Grade a parsed :class:`~pkt_core.models.Lab` submission.

    Parameters
    ----------
    submission:
        The student's :class:`~pkt_core.models.Lab` (either a ``.pka`` activity
        or a ``.pkt`` topology).
    against:
        Optional reference :class:`~pkt_core.models.Lab`. When provided:
        - If ``against`` is a ``.pka`` activity, its ``<COMPARISONS>`` tree and
          answer network are used as the authoritative rubric (preventing
          student rubric tampering).
        - If ``against`` is a ``.pkt`` topology, its network is used as the
          solution network.
    target_name:
        Label recorded on :attr:`GradeReport.target`.
    pass_threshold:
        Minimum score percentage (``0.0``–``100.0``) required for
        :attr:`GradeReport.passed` to be ``True`` (default ``100.0``).
    categories:
        Optional filter of component categories (e.g. ``{"Ip", "Routing"}``).
    """
    t0 = time.perf_counter()

    rubric_lab = against if against is not None else submission
    student_net = submission.working_network

    allowed_cats: frozenset[str] | None = None
    if categories is not None:
        allowed_cats = frozenset(c.strip().lower() for c in categories if c.strip())

    student_states = _extract_network_state(student_net)

    # Determine answer network & initial network
    if rubric_lab.is_activity:
        answer_net = rubric_lab.answer_network
        initial_net = rubric_lab.initial_network
        mode = "pka-master" if against is not None else "pka-embedded"
    else:
        answer_net = rubric_lab.working_network if against is not None else None
        initial_net = None
        mode = "pkt-against-solution" if against is not None else "pkt-self"

    answer_states = _extract_network_state(answer_net) if answer_net is not None else {}
    initial_states = _extract_network_state(initial_net) if initial_net is not None else None

    # 1. Try explicit <COMPARISONS> tree checks first
    tree_checks, has_explicit_ct = (
        _collect_Explicit_tree_checks(
            rubric_lab.scoring_tree,
            rubric_lab.initial_scoring_tree,
        )
        if rubric_lab.is_activity
        else ([], False)
    )

    items: list[GradeItem] = []

    if answer_states and not has_explicit_ct:
        # Derive comprehensive rubric from answer network (and merge any explicit tree point weights/feedback)
        tree_meta: dict[tuple[str, str], tuple[int, str]] = {
            (dname, rel): (pts, fb) for dname, rel, _lbl, _exp, pts, fb, _cat in tree_checks
        }
        rubric_checks = _derive_rubric_checks(answer_states, initial_states)
        for dname, cat, label, path_key, expected, default_pts in rubric_checks:
            if allowed_cats is not None and cat.lower() not in allowed_cats:
                continue
            pts, fb = tree_meta.get((dname, path_key), (default_pts, ""))
            st = student_states.get(dname)
            actual = _lookup_actual_value(st, path_key)
            ok = actual == expected
            items.append(
                GradeItem(
                    device=dname,
                    category=cat,
                    item=label,
                    path=f"{dname}/{path_key}",
                    expected=expected,
                    actual=actual,
                    passed=ok,
                    points_earned=pts if ok else 0,
                    points_possible=pts,
                    feedback="" if ok else fb,
                )
            )
    elif tree_checks:
        for dname, rel_path, label, expected, pts, fb, cat in tree_checks:
            if allowed_cats is not None and cat.lower() not in allowed_cats:
                continue
            st = student_states.get(dname)
            actual = _lookup_actual_value(st, rel_path)
            ok = actual == expected
            items.append(
                GradeItem(
                    device=dname,
                    category=cat,
                    item=label,
                    path=f"{dname}/{rel_path}",
                    expected=expected,
                    actual=actual,
                    passed=ok,
                    points_earned=pts if ok else 0,
                    points_possible=pts,
                    feedback="" if ok else fb,
                )
            )
    else:
        raise ValueError(
            f"{target_name}: plain .pkt files do not embed an answer network; "
            "pass against=<solution_lab> (or --against solution.pkt)"
        )

    # Aggregate per-device scores
    by_dev: dict[str, list[GradeItem]] = {}
    for it in items:
        by_dev.setdefault(it.device, []).append(it)

    dev_scores: list[DeviceScore] = []
    for dname, ditems in by_dev.items():
        model = (
            (answer_states[dname].model if dname in answer_states else "")
            or (student_states[dname].model if dname in student_states else "?")
        )
        dev_scores.append(
            DeviceScore(
                device=dname,
                model=model,
                points_earned=sum(i.points_earned for i in ditems),
                points_possible=sum(i.points_possible for i in ditems),
                items_passed=sum(1 for i in ditems if i.passed),
                items_total=len(ditems),
            )
        )

    total_earned = sum(i.points_earned for i in items)
    total_possible = sum(i.points_possible for i in items)
    pct = 100.0 if total_possible <= 0 else (total_earned / total_possible) * 100.0
    is_pass = pct + 1e-9 >= pass_threshold

    feedback = ""
    if rubric_lab.is_activity:
        feedback = rubric_lab.complete_feedback if is_pass else rubric_lab.incomplete_feedback

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return GradeReport(
        target=target_name,
        mode=mode,
        points_earned=total_earned,
        points_possible=total_possible,
        items=tuple(items),
        devices=tuple(dev_scores),
        pass_threshold=pass_threshold,
        feedback=feedback,
        elapsed_ms=elapsed_ms,
    )


_PKT_BLOCK_RE = re.compile(rb"<PACKETTRACER5\b[^>]*>.*?</PACKETTRACER5>", re.S)
_ALWAYS_TAGS: tuple[bytes, ...] = (
    b"VERSION",
    b"OVERALL_INCOMPLETE_FEEDBACK",
    b"OVERALL_COMPLETE_FEEDBACK",
    b"COMPONENT_LIST",
)
_EXPLICIT_CT_RE = re.compile(rb'checkType=["\'][1-9]')
_NONEMPTY_FB_RE = re.compile(rb'incorrectFeedback=["\'][^"\']+["\']')


def _slim_pkt_block(pkt_bytes: bytes) -> bytes:
    """Keep only ``<VERSION>`` and the outer ``<NETWORK>...</NETWORK>`` inside a
    ``<PACKETTRACER5>`` block, skipping megabytes of ``<PHYSICALWORKSPACE>``,
    ``<SCRIPT_MODULE>``, and ``<OPTIONS>`` that grading never reads.
    """
    a = pkt_bytes.find(b"<NETWORK>")
    b = pkt_bytes.rfind(b"</NETWORK>")
    if a < 0 or b < 0 or b < a:
        return pkt_bytes
    ver = b""
    va = pkt_bytes.find(b"<VERSION>")
    if 0 <= va < a:
        vb = pkt_bytes.find(b"</VERSION>", va)
        if vb > va:
            ver = pkt_bytes[va : vb + len(b"</VERSION>")]
    return b"<PACKETTRACER5>" + ver + pkt_bytes[a : b + len(b"</NETWORK>")] + b"</PACKETTRACER5>"


def _extract_tag_slice(xml: bytes, tag: bytes) -> bytes:
    open_t = b"<" + tag
    close_t = b"</" + tag + b">"
    sa = xml.find(open_t)
    if sa >= 0:
        after = sa + len(open_t)
        if xml[after : after + 1] in (b">", b" ", b"\t", b"\r", b"\n"):
            sb = xml.find(close_t, after)
            if sb > sa:
                return xml[sa : sb + len(close_t)]
    return b""


def _slim_xml_for_grading(xml: bytes) -> bytes:
    """Extract only the XML sections needed for grading."""
    if b"<PACKETTRACER5_ACTIVITY" in xml[:256]:
        parts: list[bytes] = [b"<PACKETTRACER5_ACTIVITY>"]
        pkt_blocks = [m.group(0) for m in _PKT_BLOCK_RE.finditer(xml)]
        for blk in pkt_blocks:
            parts.append(_slim_pkt_block(blk))
        for tag in _ALWAYS_TAGS:
            seg = _extract_tag_slice(xml, tag)
            if seg:
                parts.append(seg)
        comp_seg = _extract_tag_slice(xml, b"COMPARISONS")
        has_answer_devices = len(pkt_blocks) >= 3 and b"<DEVICE>" in pkt_blocks[2]
        if comp_seg and (
            not has_answer_devices
            or _EXPLICIT_CT_RE.search(comp_seg) is not None
            or _NONEMPTY_FB_RE.search(comp_seg) is not None
        ):
            parts.append(comp_seg)
            init_seg = _extract_tag_slice(xml, b"INITIALSETUP")
            if init_seg:
                parts.append(init_seg)
        parts.append(b"</PACKETTRACER5_ACTIVITY>")
        return b"".join(parts)
    if b"<PACKETTRACER5" in xml[:256]:
        return _slim_pkt_block(xml)
    return xml


def _load_lab_bytes(raw: bytes) -> Lab:
    stripped = raw.lstrip()
    if stripped.startswith(b"<"):
        xml = raw
    else:
        xml = decode_bytes(raw).xml
    return Lab.from_bytes(_slim_xml_for_grading(xml))


def grade_bytes(
    data: bytes,
    *,
    against: bytes | Lab | None = None,
    target_name: str = "<bytes>",
    pass_threshold: float = 100.0,
    categories: Iterable[str] | None = None,
) -> GradeReport:
    """Decode and grade raw ``.pka`` / ``.pkt`` / XML bytes."""
    sub_lab = _load_lab_bytes(data)
    ref_lab = _load_lab_bytes(against) if isinstance(against, bytes) else against
    return grade_lab(
        sub_lab,
        against=ref_lab,
        target_name=target_name,
        pass_threshold=pass_threshold,
        categories=categories,
    )


def grade_file(
    path: str | os.PathLike[str],
    *,
    against: str | os.PathLike[str] | Lab | None = None,
    pass_threshold: float = 100.0,
    categories: Iterable[str] | None = None,
) -> GradeReport:
    """Decode and grade a ``.pka`` or ``.pkt`` file on disk."""
    p = Path(path)
    t0 = time.perf_counter()
    sub_lab = _load_lab_bytes(p.read_bytes())
    ref_lab: Lab | None
    if isinstance(against, (str, os.PathLike)):
        ref_lab = _load_lab_bytes(Path(against).read_bytes())
    else:
        ref_lab = against
    rep = grade_lab(
        sub_lab,
        against=ref_lab,
        target_name=str(p),
        pass_threshold=pass_threshold,
        categories=categories,
    )
    total_ms = (time.perf_counter() - t0) * 1000.0
    return GradeReport(
        target=rep.target,
        mode=rep.mode,
        points_earned=rep.points_earned,
        points_possible=rep.points_possible,
        items=rep.items,
        devices=rep.devices,
        pass_threshold=rep.pass_threshold,
        feedback=rep.feedback,
        elapsed_ms=total_ms,
    )


def grade_batch(
    paths: Sequence[str | os.PathLike[str]],
    *,
    against: str | os.PathLike[str] | Lab | None = None,
    pass_threshold: float = 100.0,
    categories: Iterable[str] | None = None,
    max_workers: int | None = None,
) -> list[GradeReport]:
    """Grade a batch of ``.pka`` / ``.pkt`` submissions concurrently.

    If ``against`` is a file path, it is decoded and parsed *once* and shared
    across all worker threads so batch grading scales linearly.
    """
    if not paths:
        return []
    ref_lab: Lab | None
    if isinstance(against, (str, os.PathLike)):
        ref_lab = _load_lab_bytes(Path(against).read_bytes())
    else:
        ref_lab = against

    cat_tuple = tuple(categories) if categories is not None else None

    def _one(p: str | os.PathLike[str]) -> GradeReport:
        return grade_file(
            p,
            against=ref_lab,
            pass_threshold=pass_threshold,
            categories=cat_tuple,
        )

    if len(paths) == 1:
        return [_one(paths[0])]

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(_one, paths))
