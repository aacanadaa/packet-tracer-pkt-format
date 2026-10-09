#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
lab_api.py -- a small, verified library for building Packet Tracer 9 labs
programmatically (device placement, power, modules, cabling, IOS config,
end-device IPs).  Built on the pt9 codec.

Verified capabilities
---------------------
* add_device(model, name, ...)          place any harvested device model
*   power=True/False                    <ENGINE><POWER>  (off => ports down)
*   ios_config=[...]                    <ENGINE><RUNNINGCONFIG><LINE>…  applied on load
*   pc_ip=(ip,mask,gw)                  NIC <IP>/<SUBNET>/<PORT_GATEWAY>
* install_module(dev, module, bay=0)    fill an empty <SLOT> with a <MODULE>
* link(a, aport, b, bport, kind=…)      copper eCopper/eStraightThrough, serial eSerial
* save(path)

Physical placement
------------------
Every added device gets a freshly synthesized leaf in the PHYSICALWORKSPACE
rack (a `<NODE><TYPE>6</TYPE>` with a new `<UUID_STR>`), and a matching
`<WORKSPACE><PHYSICAL>` GUID path plus a `<PHYSICAL_CPUR>` block.  Two details
are load-critical and were found empirically:
  * the leaf UUID must be **braced** (`{uuid}`) in `<PHYSICAL>`, matching
    `<UUID_STR>`; an unbraced UUID => "corrupted Physical Workspace data".
  * a `<PHYSICAL_CPUR>` element must be present on the device.
The seed's devices (and their workspace leaves) are removed automatically so no
orphan leaves remain (orphans also corrupt the workspace).

See docs/CAPABILITIES.md for the full documented model.
"""
import os
import re
import copy
import uuid
import xml.etree.ElementTree as ET

import pt9


# --------------------------------------------------------------------------- #
# harvesting device / module templates from existing .pkt files
# --------------------------------------------------------------------------- #
def _iter_devices(xml):
    return re.finditer(rb"<DEVICE>.*?</DEVICE>", xml, re.S)


def load_templates(path):
    """Load the shipped device/module template library.  Returns (models, modules)
    where models maps model -> <DEVICE> bytes and modules maps module -> <SLOT> str.
    Handles the gzip+base64 encoding used by tools/device_templates.json."""
    import base64
    import gzip
    import json
    t = json.load(open(path))
    gz = t.get("gz", False)

    def dec(v):
        b = base64.b64decode(v)
        return gzip.decompress(b) if gz else b

    return ({k: dec(v) for k, v in t["models"].items()},
            {k: dec(v).decode("utf-8") for k, v in t.get("modules", {}).items()})


def harvest_models(saves_dir, wanted=None):
    """Return {model: <DEVICE> bytes} taking the first instance of each model."""
    import glob
    out = {}
    files = sorted(glob.glob(os.path.join(saves_dir, "**", "*.pkt"), recursive=True),
                   key=os.path.getsize)
    for f in files:
        if wanted and wanted <= set(out):
            break
        try:
            xml = pt9.decode(f, "pkt", verify_tag=False)
        except Exception:
            continue
        for m in _iter_devices(xml):
            mm = re.search(rb'<TYPE[^>]*model="([^"]*)"', m.group(0))
            if not mm:
                continue
            model = mm.group(1).decode()
            if (wanted is None or model in wanted) and model not in out:
                out[model] = m.group(0)
    return out


def harvest_modules(saves_dir, wanted):
    """Return {module_model: <SLOT> xml bytes} for modules found in devices."""
    import glob
    out = {}
    for f in sorted(glob.glob(os.path.join(saves_dir, "**", "*.pkt"), recursive=True),
                   key=os.path.getsize):
        if wanted <= set(out):
            break
        try:
            xml = pt9.decode(f, "pkt", verify_tag=False).decode("utf-8", "replace")
        except Exception:
            continue
        for model in set(re.findall(r"<MODEL>([^<]+)</MODEL>", xml)) & wanted:
            if model in out:
                continue
            i = xml.find("<MODEL>%s</MODEL>" % model)
            a = xml.rfind("<SLOT>", 0, i)
            b = xml.find("</SLOT>", i) + len("</SLOT>")
            if a >= 0 and b > a:
                out[model] = xml[a:b]
    return out


# --------------------------------------------------------------------------- #
# builder
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, seed_pkt, models, modules=None):
        seed = open(seed_pkt, "rb").read()
        xml = pt9.decode_bytes(seed, "pkt") if seed_pkt.lower().endswith(".pkt") else seed
        self.base = ET.fromstring(xml)
        self.net = self.base.find("NETWORK")
        self.devs = self.net.find("DEVICES")
        self.models = models
        self.modules = modules or {}
        self._pw = self.base.find("PHYSICALWORKSPACE")
        self._wsroot = self._pw.find("NODE") if self._pw is not None else None

        existing = self.devs.findall("DEVICE")
        # donor <PHYSICAL_CPUR> (structure template) from the seed's first device
        self._donor_cpur = None
        donor_pp = donor_cid = None
        if existing:
            dc = existing[0].find("WORKSPACE/PHYSICAL_CPUR")
            if dc is not None:
                self._donor_cpur = copy.deepcopy(dc)
                donor_pp = dc.findtext("PARENT_PATH")
                donor_cid = dc.findtext("CONTAINER_ID")
        self._PP = donor_pp or (self._pw.findtext("HOMERACK") if self._pw is not None else None)
        self._rack = self._find_container(donor_cid)
        if self._rack is None or not self._PP or not self._CID:
            raise ValueError("seed has no usable physical workspace (need HOMERACK + a Rack container)")

        self._initial_devs = list(existing)
        self._n = 0
        self._pos = 4
        self._mac = 0x2000
        self._els = {}

    # -- physical workspace helpers ---------------------------------------- #
    def _find_container(self, cid):
        """Find the container NODE (the Rack) and set self._CID to its UUID."""
        root = self._wsroot
        if root is None:
            return None
        rack = None
        for n in root.iter("NODE"):
            u = n.findtext("UUID_STR")
            if cid and u == cid:
                self._CID = cid
                return n
            if rack is None and (n.findtext("TYPE") == "4"
                                 or "rack" in (n.findtext("NAME") or "").lower()):
                rack = n
        if rack is not None:
            self._CID = rack.findtext("UUID_STR")
        return rack

    def _add_leaf(self, name, leaf, x=0):
        ch = self._rack.find("CHILDREN")
        if ch is None:
            ch = ET.SubElement(self._rack, "CHILDREN")
        el = ET.fromstring(
            "<NODE><X>{x}</X><Y>0</Y><TYPE>6</TYPE><NAME translate=\"true\">{name}</NAME>"
            "<SX>1</SX><SY>1</SY><W>0</W><H>0</H><D>0</D>"
            "<PATH isanim=\"false\">../art/Background/grid_100x100.png</PATH><CHILDREN/>"
            "<MANUAL_SCALING>false</MANUAL_SCALING><SCALED_PIXMAP_WIDTH>0</SCALED_PIXMAP_WIDTH>"
            "<SCALED_PIXMAP_HEIGHT>0</SCALED_PIXMAP_HEIGHT><INIT_WIDTH>0</INIT_WIDTH><INIT_HEIGHT>0</INIT_HEIGHT>"
            "<INIT_DEPTH>0</INIT_DEPTH><INIT_SX>1</INIT_SX><INIT_SY>1</INIT_SY><INIT_SZ>1</INIT_SZ>"
            "<BG_TILED>false</BG_TILED><CUSTOM_IMAGE_WIDTH>-1</CUSTOM_IMAGE_WIDTH>"
            "<CUSTOM_IMAGE_HEIGHT>-1</CUSTOM_IMAGE_HEIGHT><SCALE_FACTOR>1</SCALE_FACTOR>"
            "<UUID_STR>{{{u}}}</UUID_STR><SLOT>0</SLOT><SUB_SLOT>0</SUB_SLOT>"
            "<ICP_CSX>0</ICP_CSX><ICP_CSY>0</ICP_CSY></NODE>".format(x=x, name=name, u=leaf))
        ch.append(el)

    def _make_cpur(self, x):
        """Return a <PHYSICAL_CPUR> string placed in the rack at position x."""
        c = copy.deepcopy(self._donor_cpur) if self._donor_cpur is not None else ET.fromstring(
            "<PHYSICAL_CPUR><X_PN>0.03175</X_PN><Y_PN>0.134</Y_PN><X>0</X><Y>0</Y>"
            "<SLOT>0</SLOT><SUBSLOT>0</SUBSLOT><PARENT_PATH></PARENT_PATH>"
            "<CONTAINER_ID></CONTAINER_ID><ICP_CONTAINER_SCENE_X>0</ICP_CONTAINER_SCENE_X>"
            "<ICP_CONTAINER_SCENE_Y>0</ICP_CONTAINER_SCENE_Y>"
            "<ORIGINAL_DEVICE_UUID></ORIGINAL_DEVICE_UUID></PHYSICAL_CPUR>")

        def set_(tag, val):
            e = c.find(tag)
            if e is None:
                e = ET.SubElement(c, tag)
            e.text = val
        set_("PARENT_PATH", self._PP)
        set_("CONTAINER_ID", self._CID)
        set_("X", str(x))
        set_("Y", "0")
        set_("SLOT", "0")
        set_("SUBSLOT", "0")
        set_("ORIGINAL_DEVICE_UUID", "{%s}" % uuid.uuid4())
        return ET.tostring(c, encoding="unicode")

    # -- devices ----------------------------------------------------------- #
    def _next_mac(self):
        self._mac += 1
        n = self._mac
        return "%04X.%04X.%04X" % (0x0212, (n >> 16) & 0xFFFF, n & 0xFFFF)

    def add_device(self, model, name, x=100, y=100, power=True, ios_config=None,
                   pc_ip=None, install=None, bay=0):
        i = self._n
        self._n += 1
        # fresh physical leaf
        leaf = str(uuid.uuid4())
        px = self._pos
        self._pos += 6
        self._add_leaf(name, leaf, x=px)
        phys = "%s,%s,{%s}" % (self._PP, self._CID, leaf)

        blk = self.models[model].decode("utf-8", "replace")
        s = re.sub(r"save-ref-id:\d+", lambda m: "save-ref-id:%d" % (9_900_000_000_000_000_000 + i), blk)
        s = re.sub(r"<NAME[^>]*>.*?</NAME>", '<NAME translate="true">%s</NAME>' % name, s, count=1, flags=re.S)
        s = re.sub(r"(<WORKSPACE>\s*<LOGICAL>\s*<X>)[^<]*(</X>\s*<Y>)[^<]*(</Y>)",
                   lambda m: m.group(1) + str(x) + m.group(2) + str(y) + m.group(3), s, count=1, flags=re.S)
        # replace PHYSICAL and rebuild PHYSICAL_CPUR
        s = re.sub(r"<PHYSICAL[^>]*>[^<]*</PHYSICAL>", "<PHYSICAL>%s</PHYSICAL>" % phys, s)
        s = re.sub(r"<PHYSICAL_CPUR>.*?</PHYSICAL_CPUR>", "", s, flags=re.S)
        cpur = self._make_cpur(px)
        s = re.sub(r"(<PHYSICAL>[^<]*</PHYSICAL>)", lambda m: m.group(1) + cpur, s, count=1)
        el = ET.fromstring(s)
        for tag in ("MACADDRESS", "BIA"):
            for e in el.iter(tag):
                e.text = self._next_mac()
        eng = el.find("ENGINE")
        for e in list(eng.findall("SAVE_REF_ID")):
            eng.remove(e)
        sid = "save-ref-id:%d" % (9_900_000_000_000_000_000 + i)
        ET.SubElement(eng, "SAVE_REF_ID").text = sid
        if not power:
            p = eng.find("POWER")
            if p is None:
                p = ET.SubElement(eng, "POWER")
            p.text = "false"
        if ios_config:
            for rc in list(eng.findall("RUNNINGCONFIG")):
                eng.remove(rc)
            rc = ET.SubElement(eng, "RUNNINGCONFIG")
            for L in ios_config:
                ET.SubElement(rc, "LINE").text = L
        if pc_ip:
            port = el.find(".//PORT")
            for tag, val in (("IP", pc_ip[0]), ("SUBNET", pc_ip[1]),
                             ("PORT_GATEWAY", pc_ip[2]), ("PORT_DHCP_ENABLE", "false")):
                e = port.find(tag)
                if e is None:
                    e = ET.SubElement(port, tag)
                e.text = val
        self.devs.append(el)
        self._els[sid] = el
        if install:
            self.install_module(sid, install, bay)
        return sid

    def install_module(self, dev_id, module_model, bay=0):
        """Fill the `bay`-th empty eInterfaceCard slot of a device with a module."""
        el = self._els[dev_id]
        eng = el.find("ENGINE")
        empties = [sl for sl in eng.iter("SLOT")
                   if sl.findtext("TYPE") == "eInterfaceCard" and sl.find("MODULE") is None]
        if bay >= len(empties):
            raise ValueError(f"{dev_id}: only {len(empties)} empty eInterfaceCard bays")
        slot = empties[bay]
        mod = ET.fromstring(self.modules[module_model])
        for tag in ("MACADDRESS", "BIA"):
            for e in mod.iter(tag):
                e.text = self._next_mac()
        for c in list(slot):
            slot.remove(c)
        for c in list(mod):
            slot.append(c)

    def _append_config(self, dev_id, lines):
        """Append IOS config lines to a device, before a trailing `end` if present."""
        el = self._els.get(dev_id)
        if el is None or not lines:
            return
        eng = el.find("ENGINE")
        rc = eng.find("RUNNINGCONFIG")
        if rc is None:
            rc = ET.SubElement(eng, "RUNNINGCONFIG")
        kids = list(rc)
        idx = len(kids)
        if kids and (kids[-1].text or "").strip().lower() == "end":
            idx = len(kids) - 1
        for off, l in enumerate(lines):
            e = ET.Element("LINE")
            e.text = l
            rc.insert(idx + off, e)

    def _set_serial_port(self, dev_id, port_name, rate):
        """Set CLOCKRATE / CLOCKRATEFLAG=true / POWER=true on a serial port.
        Both ends of a serial link carry POWER=true and CLOCKRATEFLAG=true; only the
        DCE end carries a non-zero CLOCKRATE.  Without these the line stays down
        (cable renders red) even if the IOS config is correct."""
        el = self._els.get(dev_id)
        if el is None:
            return
        ports = [p for p in el.iter("PORT") if p.findtext("TYPE") == "eSmartSerial"]
        if not ports:
            return
        try:
            idx = int(port_name.split("/")[-1])
        except ValueError:
            idx = 0
        if idx >= len(ports):
            idx = 0
        p = ports[idx]
        for tag, val in (("CLOCKRATE", str(rate)), ("CLOCKRATEFLAG", "true"), ("POWER", "true")):
            e = p.find(tag)
            if e is None:
                e = ET.SubElement(p, tag)
            e.text = val

    def link(self, a_id, a_port, b_id, b_port, kind="copper", dce=None, dce_port=None, clock=128000):
        """Add a cable.  kind='copper' (eCopper/eStraightThrough) or
        'serial' (eSerial; pass dce=<device id of the DCE end>).  For a serial
        link the DCE interface is given a `clock rate` automatically (without it
        the line stays down / the cable renders red)."""
        L = ET.SubElement(self.net.find("LINKS"), "LINK")
        ET.SubElement(L, "TYPE").text = "eCopper" if kind == "copper" else ("eSerial" if kind == "serial" else None)
        cab = ET.SubElement(L, "CABLE")
        if kind == "copper":
            fields = [("LENGTH", "1"), ("FUNCTIONAL", "true"), ("FROM", a_id), ("PORT", a_port),
                      ("TO", b_id), ("PORT", b_port), ("FROM_DEVICE_MEM_ADDR", "1"), ("TO_DEVICE_MEM_ADDR", "2"),
                      ("FROM_PORT_MEM_ADDR", "3"), ("TO_PORT_MEM_ADDR", "4"),
                      ("GEO_VIEW_COLOR", "#6ba72e"), ("IS_MANAGED_IN_RACK_VIEW", "false"),
                      ("TYPE", "eStraightThrough")]
        elif kind == "serial":
            dce = dce or a_id
            dport = dce_port or (a_port if dce == a_id else b_port)
            self._set_serial_port(a_id, a_port, clock if dce == a_id else 0)
            self._set_serial_port(b_id, b_port, clock if dce == b_id else 0)
            self._append_config(dce, ["interface %s" % dport, " clock rate %d" % clock])
            fields = [("LENGTH", "1"), ("FUNCTIONAL", "true"), ("FROM", a_id), ("PORT", a_port),
                      ("TO", b_id), ("PORT", b_port), ("FROM_DEVICE_MEM_ADDR", "1"), ("TO_DEVICE_MEM_ADDR", "2"),
                      ("FROM_PORT_MEM_ADDR", "3"), ("TO_PORT_MEM_ADDR", "4"),
                      ("GEO_VIEW_COLOR", "#1e59a5"), ("IS_MANAGED_IN_RACK_VIEW", "false"),
                      ("DCEDEV", dce), ("DCEPORT", dport)]
        else:
            raise ValueError("kind must be 'copper' or 'serial'")
        for t, v in fields:
            ET.SubElement(cab, t).text = v

    def set_os(self, dev_id, image=None, file_name=None):
        """Set a device's OS image / boot file (`<OS_IMAGE>`, `<OS_FILE_NAME>`)."""
        eng = self._els[dev_id].find("ENGINE")
        for tag, val in (("OS_IMAGE", image), ("OS_FILE_NAME", file_name)):
            if val is None:
                continue
            e = eng.find(tag)
            if e is None:
                e = ET.SubElement(eng, tag)
            e.text = val

    def set_config_register(self, dev_id, value):
        eng = self._els[dev_id].find("ENGINE")
        e = eng.find("CONFIG_REGISTER")
        if e is None:
            e = ET.SubElement(eng, "CONFIG_REGISTER")
        e.text = str(value)

    def initial_id(self, index=0):
        eng = self._initial_devs[index].find("ENGINE")
        sid = eng.find("SAVE_REF_ID")
        return sid.text if sid is not None else None

    def drop_initial(self):
        """Remove the seed's own devices, their workspace leaves, and any links that
        referenced them (dangling links / orphan leaves corrupt the file)."""
        dead = set()
        for el in self._initial_devs:
            eng = el.find("ENGINE")
            sid = eng.findtext("SAVE_REF_ID")
            if sid:
                dead.add(sid)
            ph = el.findtext("WORKSPACE/PHYSICAL")
            if ph and self._wsroot is not None:
                leaf = "{%s}" % ph.split(",")[-1].strip().strip("{}")
                for n in list(self._wsroot.iter("NODE")):
                    if n.findtext("UUID_STR") == leaf:
                        for parent in self._wsroot.iter("NODE"):
                            ch = parent.find("CHILDREN")
                            if ch is not None and n in list(ch):
                                ch.remove(n)
            if el in list(self.devs):
                self.devs.remove(el)
        links = self.net.find("LINKS")
        if links is not None and dead:
            for L in list(links.findall("LINK")):
                cab = L.find("CABLE")
                if cab is not None and (cab.findtext("FROM") in dead or cab.findtext("TO") in dead):
                    links.remove(L)
        self._initial_devs = []

    def save(self, path):
        pt9.encode(path, ET.tostring(self.base, encoding="unicode").encode("utf-8"), "pkt")


if __name__ == "__main__":
    import sys
    print("lab_api: import and use class Lab(). See docs/CAPABILITIES.md")
