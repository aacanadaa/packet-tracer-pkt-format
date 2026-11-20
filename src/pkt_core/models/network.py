"""Network-level models: devices, ports, modules, links and canvas placement."""

from __future__ import annotations

from typing import ClassVar, Literal, TypeAlias

from pkt_core.models.base import PktNode
from pkt_core.models.schema import (
    DeviceDetails,
    FileEntry,
    PortConfig,
    WirelessConfig,
)
from pkt_core.models.services import DeviceServices
from pkt_core.xml.nodes import XmlElement, XmlText, escape_xml_text

__all__ = ["Port", "Module", "Workspace", "Device", "Cable", "Link", "PowerState"]


PowerState: TypeAlias = Literal["true", "false", "absent"]
"""The three ``<ENGINE><POWER>`` states seen in real Packet Tracer documents.

Corpus semantics (5,819 devices across 443 decodable saves):

* ``"true"``  -- powered on: the state of every working device. All 28 device
  kinds carry the element (PCs, servers, MCU/IoT components and access points
  included), so no kind is exempt.
* ``"false"`` -- powered off, used for deliberately staged-off gear.
* ``"absent"`` -- the element is missing (or empty). Packet Tracer never omits
  ``<POWER>`` (0 of 5,819 corpus devices), so absence is a generator artefact
  with no author-defined meaning; PT's behaviour on it is unverified. Treat it
  as unsupported rather than as "on".
"""


class Port(PktNode):
    """A physical interface on a device.

    Covers the interface table: media type, link speed, duplex, MAC/BIA and
    serial clocking. Anything unrecognised stays in ``extra_fields``.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "TYPE", "POWER", "MEDIATYPE", "PINS", "BANDWIDTH", "FULLDUPLEX",
            "AUTONEGOTIATEBANDWIDTH", "AUTONEGOTIATEDUPLEX", "MACADDRESS",
            "BIA", "CLOCKRATE", "CLOCKRATEFLAG", "DESCRIPTION", "CHANNEL",
            "CHANNEL5GHZ", "COVERAGERANGE", "SAVED_FULLDUPLEX", "UP_METHOD",
        }
    )

    @property
    def type(self) -> str:
        """Media/port kind, e.g. ``eCopperFastEthernet``."""
        return self._text("TYPE")

    @property
    def power(self) -> bool:
        """Whether the port is administratively powered on (defaults to True)."""
        return self._bool("POWER", default=True)

    @property
    def mac_address(self) -> str:
        return self._text("MACADDRESS")

    @property
    def burned_in_address(self) -> str:
        """Hardware (BIA) MAC, as opposed to the configured one."""
        return self._text("BIA")

    @property
    def bandwidth(self) -> int:
        return self._int("BANDWIDTH")

    @property
    def full_duplex(self) -> bool:
        return self._bool("FULLDUPLEX")

    @property
    def auto_negotiate_duplex(self) -> bool:
        return self._bool("AUTONEGOTIATEDUPLEX")

    @property
    def clock_rate(self) -> int:
        return self._int("CLOCKRATE")

    @property
    def channel(self) -> int:
        return self._int("CHANNEL")

    @property
    def description(self) -> str:
        return self._text("DESCRIPTION")


class Module(PktNode):
    """A plug-in module, itself containing slots, sub-modules and ports.

    Packet Tracer nests these: ``MODULE -> SLOT -> MODULE -> PORT``. The nesting
    is preserved exactly as written; :attr:`ports` flattens it for convenience.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset({"TYPE", "MODEL", "SLOT", "MODULE", "PORT"})

    @property
    def type(self) -> str:
        return self._text("TYPE")

    @property
    def model(self) -> str:
        return self._text("MODEL")

    @property
    def slots(self) -> list["Module"]:
        """Sub-modules reached through a ``<SLOT>`` wrapper."""
        out: list[Module] = []
        for slot in self._children("SLOT"):
            for mod in slot.find_all("MODULE"):
                out.append(Module.from_element(mod))
        return out

    @property
    def submodules(self) -> list["Module"]:
        return [Module.from_element(m) for m in self._children("MODULE")]

    @property
    def ports(self) -> list[Port]:
        return [Port.from_element(p) for p in self._children("PORT")]

    @property
    def all_ports(self) -> list[Port]:
        """Every port in this module subtree, depth first."""
        found: list[Port] = list(self.ports)
        for sub in self.submodules:
            found.extend(sub.all_ports)
        for slot in self.slots:
            found.extend(slot.all_ports)
        return found


class Workspace(PktNode):
    """Canvas placement of a device.

    ``LOGICAL`` holds the topology-view coordinates and cluster membership;
    ``PHYSICAL`` holds the rack/physical-workspace GUID path.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset({"LOGICAL", "PHYSICAL", "PHYSICAL_CPUR"})

    @property
    def logical(self) -> XmlElement | None:
        return self._el.find("LOGICAL")

    @property
    def x(self) -> float:
        node = self.logical
        child = node.find("X") if node is not None else None
        if child is None:
            return 0.0
        try:
            return float(child.text.strip())
        except ValueError:
            return 0.0

    @property
    def y(self) -> float:
        node = self.logical
        child = node.find("Y") if node is not None else None
        if child is None:
            return 0.0
        try:
            return float(child.text.strip())
        except ValueError:
            return 0.0

    @property
    def cluster_id(self) -> str:
        """Cluster membership, e.g. ``1-1`` for the root cluster."""
        node = self.logical
        child = node.find("DEVCLUSTERID") if node is not None else None
        return child.text.strip() if child is not None else ""

    @property
    def physical_path(self) -> str:
        """GUID path into the physical workspace, as raw text."""
        return self._text("PHYSICAL")

    @property
    def dev_addr(self) -> str:
        node = self.logical
        if node is not None:
            child = node.find("DEV_ADDR")
            if child is not None:
                val = child.text.strip()
                if val:
                    return val
        return self._text("DEV_ADDR")

    @property
    def mem_addr(self) -> str:
        node = self.logical
        if node is not None:
            child = node.find("MEM_ADDR")
            if child is not None:
                val = child.text.strip()
                if val:
                    return val
        return self._text("MEM_ADDR")


class Device(PktNode):
    """A network device: router, switch, PC, server, AP, IoT component, ...

    The chassis is ``(kind, model)`` - e.g. ``("Switch", "2960-24TT")`` or
    ``("Pc", "PC-PT")``. Both come from the ``<TYPE>`` element's text and its
    ``model`` attribute.
    """

    _claimed: ClassVar[frozenset[str]] = frozenset({"ENGINE", "WORKSPACE"})

    @property
    def engine(self) -> XmlElement | None:
        return self._el.find("ENGINE")

    def _engine(self) -> XmlElement:
        node = self.engine
        if node is None:
            raise ValueError("device has no <ENGINE>")
        return node

    @property
    def kind(self) -> str:
        """Device family as Packet Tracer names it (``Switch``, ``Router``, ``Pc``...)."""
        engine = self.engine
        node = engine.find("TYPE") if engine is not None else None
        return node.text.strip() if node is not None else ""

    @property
    def model(self) -> str:
        """Chassis model, from the ``<TYPE model="...">`` attribute."""
        engine = self.engine
        node = engine.find("TYPE") if engine is not None else None
        return node.get("model") or "" if node is not None else ""

    @property
    def custom_model(self) -> str:
        engine = self.engine
        node = engine.find("TYPE") if engine is not None else None
        return node.get("customModel") or "" if node is not None else ""

    @property
    def name(self) -> str:
        engine = self.engine
        node = engine.find("NAME") if engine is not None else None
        return node.text.strip() if node is not None else ""

    @property
    def save_ref_id(self) -> str:
        """Device reference identifier (``<ENGINE><SAVE_REF_ID>``), e.g. ``save-ref-id:...``."""
        engine = self.engine
        node = engine.find("SAVE_REF_ID") if engine is not None else None
        return node.text.strip() if node is not None else ""

    def set_name(self, value: str) -> None:
        """Rename the device.

        The name lives under ``<DEVICE><ENGINE><NAME>``, not as a direct child
        of ``<DEVICE>`` - using the generic setter would create a second,
        ignored ``<NAME>`` and leave the device unchanged.
        """
        engine = self._engine()
        node = engine.find("NAME")
        if node is None:
            node = XmlElement(name=b"NAME")
            engine.append(node)
        node.children = [XmlText(data=escape_xml_text(value).encode("utf-8"))]
        node._dirty = True
        engine._dirty = True
        self._el._dirty = True

    def set_position(self, x: float, y: float) -> None:
        """Move the device on the logical canvas."""
        node = self._el.find("WORKSPACE")
        if node is None:
            node = XmlElement(name=b"WORKSPACE")
            self._el.append(node)
        logical = node.find("LOGICAL")
        if logical is None:
            logical = XmlElement(name=b"LOGICAL")
            node.append(logical)
        for tag, val in (("X", str(x)), ("Y", str(y))):
            field = logical.find(tag)
            if field is None:
                field = XmlElement(name=tag.encode("utf-8"))
                logical.append(field)
            field.children = [XmlText(data=val.encode("utf-8"))]
            field._dirty = True
        logical._dirty = True
        node._dirty = True
        self._el._dirty = True

    @property
    def power_state(self) -> PowerState:
        """The raw ``<ENGINE><POWER>`` state: ``"true"``, ``"false"`` or ``"absent"``.

        The three states are semantically distinct (see :data:`PowerState`):
        ``"false"`` is a deliberate power-off, while ``"absent"`` means the
        element is missing or empty and is a generator artefact Packet Tracer
        itself never writes.  Any other text is reported as ``"false"``, which
        is how Packet Tracer and :attr:`powered` treat it.

        This is the device-level element only; per-port ``<PORT><POWER>`` is a
        different field with its own semantics (unused ports legitimately ship
        ``false``/absent) and is exposed via :class:`Port`.
        """
        engine = self.engine
        node = engine.find("POWER") if engine is not None else None
        if node is None:
            return "absent"
        text = node.text.strip()
        if not text:
            return "absent"
        return "true" if text.lower() == "true" else "false"

    @property
    def powered(self) -> bool:
        """Whether the device is powered on.

        Reads exactly ``power_state == "true"``: ``"false"`` **and** ``"absent"``
        both count as off.  Use :attr:`power_state` when the two off-states must
        be distinguished.
        """
        return self.power_state == "true"

    @property
    def description(self) -> str:
        engine = self.engine
        node = engine.find("DESCRIPTION") if engine is not None else None
        return node.text.strip() if node is not None else ""

    @property
    def modules(self) -> list[Module]:
        engine = self.engine
        if engine is None:
            return []
        return [Module.from_element(m) for m in engine.find_all("MODULE")]

    @property
    def ports(self) -> list[Port]:
        """Every interface on the device, flattened across modules and slots."""
        out: list[Port] = []
        for mod in self.modules:
            out.extend(mod.all_ports)
        return out

    @property
    def workspace(self) -> Workspace | None:
        node = self._el.find("WORKSPACE")
        return Workspace.from_element(node) if node is not None else None

    @property
    def position(self) -> tuple[float, float]:
        """Canvas ``(x, y)`` in the logical topology view."""
        ws = self.workspace
        return (ws.x, ws.y) if ws is not None else (0.0, 0.0)

    @property
    def cluster_id(self) -> str:
        ws = self.workspace
        return ws.cluster_id if ws is not None else ""

    # -- extended schema families -----------------------------------------
    @property
    def details(self) -> DeviceDetails | None:
        """Inventory metadata: sys contact/location, serial, physical coords."""
        node = self.engine
        return DeviceDetails.from_element(node) if node is not None else None

    @property
    def services(self) -> DeviceServices | None:
        """Service record lists (AAA clients, DHCP pools, DNS records, ...)."""
        node = self.engine
        return DeviceServices.from_element(node) if node is not None else None

    @property
    def port_configs(self) -> list[PortConfig]:
        """IP/DHCP/DNS/VLAN configuration blocks found under this device."""
        engine = self.engine
        if engine is None:
            return []
        out: list[PortConfig] = []
        for node in engine.iter_elements():
            if node.tag in ("PORT_CONFIG", "IP_CONFIG", "SETTINGS", "CONFIG"):
                out.append(PortConfig.from_element(node))
            elif node.tag == "PORT" and (
                node.find("IP") is not None or node.find("IP_ADDRESS") is not None
            ):
                out.append(PortConfig.from_element(node))
        return out

    @property
    def wireless(self) -> WirelessConfig | None:
        engine = self.engine
        if engine is None:
            return None
        for node in engine.iter_elements():
            if node.tag in ("WIRELESS_CLIENT", "WIRELESS_COMMON", "WIRELESS_PROFILE"):
                return WirelessConfig.from_element(node)
        return None

    @property
    def files(self) -> list[FileEntry]:
        """Entries in the device's simulated filesystem."""
        engine = self.engine
        if engine is None:
            return []
        out: list[FileEntry] = []
        for node in engine.iter_elements():
            if node.tag in ("FILE", "FILE_DATA_ENTRY", "PORT_DATA_ENTRY"):
                out.append(FileEntry.from_element(node))
        return out

    @property
    def dev_addr(self) -> str:
        """Internal device address.

        This is what cables reference as ``<FROM_DEVICE_MEM_ADDR>`` /
        ``<TO_DEVICE_MEM_ADDR>``, and is one way to resolve a link endpoint
        back to a device alongside :attr:`save_ref_id` (``<ENGINE><SAVE_REF_ID>``).
        """
        ws = self.workspace
        return ws.dev_addr if ws is not None else ""


class Cable(PktNode):
    """The physical cable behind a link, including which ports it joins."""

    _claimed: ClassVar[frozenset[str]] = frozenset(
        {
            "LENGTH", "FUNCTIONAL", "FROM", "PORT", "TO",
            "FROM_DEVICE_MEM_ADDR", "TO_DEVICE_MEM_ADDR",
            "FROM_PORT_MEM_ADDR", "TO_PORT_MEM_ADDR",
            "GEO_VIEW_COLOR", "TYPE",
        }
    )

    @property
    def length(self) -> float:
        return self._float("LENGTH")

    @property
    def functional(self) -> bool:
        return self._bool("FUNCTIONAL")

    @property
    def cable_type(self) -> str:
        """``eStraightThrough``, ``eCrossOver``, ``eCopper``, ..."""
        return self._text("TYPE")

    @property
    def geo_view_color(self) -> str:
        return self._text("GEO_VIEW_COLOR")

    @property
    def from_ref(self) -> str:
        """Device reference, e.g. ``save-ref-id:4243533359921966632``."""
        return self._text("FROM")

    @property
    def to_ref(self) -> str:
        return self._text("TO")

    @property
    def endpoints(self) -> tuple[str, str]:
        """``(from_ref, to_ref)`` device references."""
        return (self.from_ref, self.to_ref)

    @property
    def from_device_addr(self) -> str:
        """Device address of the ``FROM`` end, used to resolve to a device name."""
        return self._text("FROM_DEVICE_MEM_ADDR")

    @property
    def to_device_addr(self) -> str:
        return self._text("TO_DEVICE_MEM_ADDR")

    @property
    def ports(self) -> list[str]:
        """The two port names, in ``FROM`` then ``TO`` order.

        Packet Tracer writes two ``<PORT>`` elements in that order; the pairing
        is positional, so this returns them as a list rather than guessing.
        """
        return [p.text.strip() for p in self._children("PORT")]


class Link(PktNode):
    """A layer-1/2 connection between two device ports."""

    _claimed: ClassVar[frozenset[str]] = frozenset({"TYPE", "CABLE"})

    @property
    def type(self) -> str:
        """Link media class, e.g. ``eCopper``."""
        return self._text("TYPE")

    @property
    def cable(self) -> Cable | None:
        node = self._el.find("CABLE")
        return Cable.from_element(node) if node is not None else None

    @property
    def endpoints(self) -> tuple[str, str] | None:
        cable = self.cable
        return cable.endpoints if cable is not None else None

    @property
    def port_names(self) -> list[str]:
        cable = self.cable
        return cable.ports if cable is not None else []

    @property
    def cable_type(self) -> str:
        """Cable kind, or ``""`` for links with no cable (e.g. wireless)."""
        cable = self.cable
        return cable.cable_type if cable is not None else ""
