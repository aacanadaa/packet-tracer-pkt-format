#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
scoring.py -- generate Packet Tracer activity scoring trees
(`<INITIALSETUP>` / `<COMPARISONS>`) for `tools/activity.py`.

IMPORTANT (reverse-engineered behaviour): Packet Tracer **validates the scoring
tree against the network's item model**.  A hand-made minimal node is rejected
(the activity fails to open with a misleading "requires version …" error), while
a *complete* device node cloned from a real activity loads fine.  Therefore the
reliable way to author scoring offline is to **clone complete item nodes from a
reference activity** and retarget/rename them, optionally overriding the expected
values.

    init, comp = scoring.from_template(template_xml,
                                       devices=["R1", "SW1", "PC1"],
                                       overrides={"R1": {"IP Address": "192.168.9.1"}})
    activity.Activity(tpl).set_scoring_xml(init, comp).save("lab.pka")

`template_xml` is the decoded XML of any activity that already contains device
nodes of the classes you need (a router activity for routers, etc.).
"""
import re
import xml.etree.ElementTree as ET


SCAFFOLD_HEAD = {"Instruction", "Resource", "ConnectivityTests", "CodeTesting"}
SCAFFOLD_TAIL = {"Remote Network", "Remote Networks", "Encircling Tests"}
SCAFFOLD_NAMES = SCAFFOLD_HEAD | SCAFFOLD_TAIL


def _section(xml, tag):
    open_tag = "<%s>" % tag
    close_tag = "</%s>" % tag
    a = xml.find(open_tag)
    if a < 0:
        raise ValueError("missing <%s> section" % tag)
    b = xml.find(close_tag, a)
    if b < 0:
        raise ValueError("unclosed <%s> section" % tag)
    return xml[a : b + len(close_tag)]


def _net_node(root):
    return root.find("NODE")


def _device_nodes(net_node):
    """Direct child NODE elements of the Network node that are devices
    (heuristic: not one of the fixed scaffolding nodes)."""
    out = []
    for c in net_node:
        if c.tag == "NODE":
            nm = c.findtext("NAME") or ""
            if nm not in SCAFFOLD_NAMES:
                out.append(c)
    return out


def _propagate_check_types(node):
    """Set ``checkType="1"`` on every ancestor of any checked leaf (``checkType > 0``).

    Returns ``True`` if ``node`` or any descendant is checked.
    """
    child_nodes = [c for c in node if c.tag == "NODE"]
    nm_el = node.find("NAME")
    if not child_nodes:
        ct = (nm_el.get("checkType") or "0") if nm_el is not None else "0"
        return ct != "0"
    any_checked = False
    for ch in child_nodes:
        if _propagate_check_types(ch):
            any_checked = True
    if nm_el is not None:
        nm_el.set("checkType", "1" if any_checked else "0")
    return any_checked


def _format_scoring_tree(net_node):
    """Indent a scoring ``<NODE>`` tree and expand empty tags.

    PT 9.0.1 silently stops parsing ``<COMPARISONS>`` / ``<INITIALSETUP>``
    device siblings after the first device when ``</NODE><NODE>`` appear with
    no intervening newline.  ``ET.indent`` guarantees newlines between every
    sibling ``<NODE>`` element.
    """
    net_node.tail = None
    ET.indent(net_node, space=" ", level=1)
    body = ET.tostring(net_node, encoding="unicode")
    body = body.replace("<COMPONENTS />", "<COMPONENTS></COMPONENTS>")
    body = body.replace("<POINTS />", "<POINTS></POINTS>")
    return body


def from_template(template_xml, devices=None, overrides=None, rename=None):
    """Clone complete device nodes from a template activity.

    devices   : keep only these device names (default: all in the template)
    rename    : {old_name: new_name}
    overrides : {device_name: {item_id_or_path: value}} to set expected values
    Returns (initialsetup_xml, comparisons_xml).
    """
    if isinstance(template_xml, bytes):
        template_xml = template_xml.decode("utf-8", "replace")
    rename = rename or {}
    overrides = overrides or {}

    def build(tag, with_scaffold):
        seg = _section(template_xml, tag)
        root = ET.fromstring(seg)
        net = _net_node(root)
        if net is None:
            raise ValueError("<%s> has no <NODE> root" % tag)
        devs = _device_nodes(net)
        head_sc, tail_sc = [], []
        if with_scaffold:
            for c in net:
                if c.tag == "NODE" and c not in devs:
                    nm = c.findtext("NAME") or ""
                    if nm in SCAFFOLD_TAIL:
                        tail_sc.append(c)
                    else:
                        head_sc.append(c)
        kept = list(head_sc)
        for d in devs:
            nm = d.findtext("NAME") or ""
            if devices is not None and nm not in devices:
                continue
            new = rename.get(nm, nm)
            clone = ET.fromstring(
                _retarget(ET.tostring(d, encoding="unicode"), new, overrides.get(new, {}))
            )
            kept.append(clone)
        kept.extend(tail_sc)
        for c in list(net):
            net.remove(c)
        for c in kept:
            net.append(c)
        body = _format_scoring_tree(net)
        if tag == "INITIALSETUP":
            return "<INITIALSETUP>\n %s\n <LOAD_INIT_TREE>true</LOAD_INIT_TREE>\n</INITIALSETUP>" % body
        return "<COMPARISONS>\n %s\n</COMPARISONS>" % body

    return build("INITIALSETUP", with_scaffold=False), build("COMPARISONS", with_scaffold=True)


# --------------------------------------------------------------------------- #
# value derivation (from an answer network) -- use with from_template overrides
# --------------------------------------------------------------------------- #
def _canonical_iface(name):
    s = name.strip()
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


def _unescape_line(line):
    return (
        line.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&apos;", "'")
        .replace("&amp;", "&")
    )


def derive_values(answer_xml):
    """Return ``{device_name: {item_id_or_path: expected_value}}`` from a decoded
    answer network (IOS running-config + end-device port/engine settings)."""
    if isinstance(answer_xml, bytes):
        answer_xml = answer_xml.decode("utf-8", "replace")
    out = {}
    for m in re.finditer(r"<DEVICE>.*?</DEVICE>", answer_xml, re.S):
        blk = m.group(0)
        nm = re.search(r"<NAME[^>]*>([^<]*)</NAME>", blk)
        if not nm:
            continue
        name = nm.group(1)
        vals = {}
        model = re.search(r'<TYPE\b[^>]*model="([^"]*)"', blk)
        if model:
            vals["Device Model"] = model.group(1)
        pwr = re.search(r"<POWER>(true|false)</POWER>", blk)
        if pwr:
            vals["Power"] = "1" if pwr.group(1) == "true" else "0"
        rc = re.search(r"<RUNNINGCONFIG>(.*?)</RUNNINGCONFIG>", blk, re.S)
        if rc:
            cur_iface = None
            iface_ip_seen = set()
            iface_shut = {}
            iface_no_shut = set()
            for raw_line in re.findall(r"<LINE>(.*?)</LINE>", rc.group(1), re.S):
                line = _unescape_line(raw_line)
                stripped = line.strip()
                if not line.startswith(" "):
                    cur_iface = None
                    if stripped.lower() == "end":
                        break
                    mh = re.match(r"hostname\s+(\S+)$", stripped, re.I)
                    if mh:
                        vals["Host Name"] = mh.group(1)
                        continue
                    mi = re.match(r"interface\s+(\S+)$", stripped, re.I)
                    if mi:
                        cur_iface = _canonical_iface(mi.group(1))
                        continue
                    continue
                if cur_iface is None:
                    continue
                ma = re.match(r"ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$", stripped, re.I)
                if ma:
                    vals[f"Ports/{cur_iface}/IP Address"] = ma.group(1)
                    vals[f"Ports/{cur_iface}/Subnet Mask"] = ma.group(2)
                    iface_ip_seen.add(cur_iface)
                    continue
                if stripped.lower() == "no shutdown":
                    iface_no_shut.add(cur_iface)
                    iface_shut[cur_iface] = False
                    continue
                if stripped.lower() == "shutdown":
                    iface_shut[cur_iface] = True
                    continue
                msw = re.match(r"switchport\s+mode\s+(\S+)$", stripped, re.I)
                if msw:
                    mode_kw = msw.group(1).lower()
                    if mode_kw == "trunk":
                        vals[f"Ports/{cur_iface}/Dynamic Mode"] = "2"
                    elif mode_kw == "access":
                        vals[f"Ports/{cur_iface}/Dynamic Mode"] = "3"
            for iface in iface_ip_seen | iface_no_shut | set(iface_shut):
                if iface in iface_no_shut or (iface in iface_ip_seen and not iface_shut.get(iface, False)):
                    vals[f"Ports/{iface}/Port Up"] = "1"
                elif iface_shut.get(iface) is True:
                    vals[f"Ports/{iface}/Port Up"] = "0"
        else:
            ip = re.search(r"<IP>([^<]+)</IP>", blk)
            mask = re.search(r"<SUBNET>([^<]+)</SUBNET>", blk)
            # PT reads end-device default gateway from <ENGINE><GATEWAY>, falling back to <PORT_GATEWAY>
            eng_no_port = re.sub(r"<MODULE>.*?</MODULE>", "", blk, flags=re.S)
            egw = re.search(r"<GATEWAY>([^<]+)</GATEWAY>", eng_no_port)
            pgw = re.search(r"<PORT_GATEWAY>([^<]+)</PORT_GATEWAY>", blk)
            gw_val = (
                egw.group(1) if (egw and egw.group(1) and egw.group(1) != "0.0.0.0")
                else (pgw.group(1) if pgw else "")
            )
            if ip and ip.group(1) and ip.group(1) != "0.0.0.0":
                vals["Ports/FastEthernet0/IP Address"] = ip.group(1)
            if mask and mask.group(1) and mask.group(1) != "0.0.0.0":
                vals["Ports/FastEthernet0/Subnet Mask"] = mask.group(1)
            if gw_val and gw_val != "0.0.0.0":
                vals["Default Gateway"] = gw_val
        out[name] = vals
    return out


def derive_from_network(answer_xml):
    """Return a list of ``{"name": ..., "model": ..., "overrides": ...}`` dicts
    suitable for :func:`from_shapes` / :func:`build` from a decoded answer network."""
    vals = derive_values(answer_xml)
    spec = []
    for name, overrides in vals.items():
        model = overrides.get("Device Model", "")
        if model:
            spec.append({"name": name, "model": model, "overrides": overrides})
    return spec


# --------------------------------------------------------------------------- #
# device-node "shape" library  (complete item nodes harvested from activities)
# --------------------------------------------------------------------------- #
import json
import glob
import os as _os


def _model_of(comp_node):
    for e in comp_node.iter("NODE"):
        if e.findtext("ID") == "Device Model":
            nm = e.find("NAME")
            return nm.get("nodeValue") if nm is not None else None
    return None


def harvest_shapes(activity_xmls):
    """Return {"scaffold": [comp node xml…], "models": {model: {"init":…, "comp":…}}}."""
    scaffold = []
    scaffold_seen = set()
    models = {}
    for xml in activity_xmls:
        if isinstance(xml, bytes):
            xml = xml.decode("utf-8", "replace")
        try:
            init_root = ET.fromstring(_section(xml, "INITIALSETUP"))
            comp_root = ET.fromstring(_section(xml, "COMPARISONS"))
        except (ET.ParseError, ValueError):
            continue
        inet, cnet = init_root.find("NODE"), comp_root.find("NODE")
        if inet is None or cnet is None:
            continue
        init_by_name = {c.findtext("NAME"): c for c in inet if c.tag == "NODE"}
        for c in cnet:
            if c.tag != "NODE":
                continue
            nm = c.findtext("NAME")
            if nm in SCAFFOLD_NAMES:
                if nm not in scaffold_seen:
                    scaffold.append(ET.tostring(c, encoding="unicode"))
                    scaffold_seen.add(nm)
                continue
            model = _model_of(c)
            if not model or model in models:
                continue
            inode = init_by_name.get(nm)
            models[model] = {
                "init": ET.tostring(inode, encoding="unicode") if inode is not None else None,
                "comp": ET.tostring(c, encoding="unicode"),
            }
    return {"scaffold": scaffold, "models": models}


def save_shapes(shapes, path):
    import gzip
    with open(path, "wb") as fh:
        fh.write(gzip.compress(json.dumps(shapes).encode("utf-8"), 9))


def load_shapes(path=None):
    import gzip
    if path is None:
        path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "device_shapes.json")
    with open(path, "rb") as fh:
        b = fh.read()
    if b[:2] == b"\x1f\x8b":
        b = gzip.decompress(b)
    return json.loads(b)


def _retarget(node_xml, name, overrides, *, enable_checks=False):
    el = ET.fromstring(node_xml)
    old = el.findtext("NAME")
    for e in el.iter("NAME"):
        if e.text == old:
            e.text = name
        if enable_checks:
            e.set("checkType", "0")
    for e in el.iter("ID"):
        if e.text == old:
            e.text = name

    ov = overrides or {}

    def apply_overrides(node, rel_path=""):
        child_nodes = [c for c in node if c.tag == "NODE"]
        if rel_path:
            lbl = node.findtext("NAME") or ""
            idn = node.findtext("ID") or ""
            matched_val = None
            matched_key = None
            if rel_path in ov:
                matched_val = ov[rel_path]
                matched_key = rel_path
            elif "/" not in rel_path and (lbl in ov or idn in ov):
                matched_key = lbl if lbl in ov else idn
                matched_val = ov[matched_key]
            elif "/" in rel_path and not child_nodes:
                # Backward compatibility for flat keys on leaves (excluding ambiguous 'Power')
                for k, v in ov.items():
                    if "/" not in k and k != "Power" and (lbl == k or idn == k):
                        matched_val = v
                        matched_key = k
                        break
            if matched_key is not None:
                nmel = node.find("NAME")
                if nmel is not None:
                    nmel.set("nodeValue", str(matched_val))
                    if enable_checks and matched_key != "Device Model":
                        nmel.set("checkType", "2")
        for ch in child_nodes:
            cid = ch.findtext("ID") or ch.findtext("NAME") or ""
            sub_path = f"{rel_path}/{cid}" if rel_path else cid
            apply_overrides(ch, sub_path)

    apply_overrides(el)
    return ET.tostring(el, encoding="unicode")


def from_shapes(spec, shapes=None, *, enable_checks=True):
    """Build (initialsetup_xml, comparisons_xml) from harvested shapes.

    spec: [{"name": "R9", "model": "2911", "overrides": {...}}, ...]
    """
    if shapes is None:
        shapes = load_shapes()
    init_nodes, comp_nodes = [], []
    missing = []
    for d in spec:
        model = d["model"]
        if model not in shapes["models"]:
            missing.append(model)
            continue
        sh = shapes["models"][model]
        if sh.get("init"):
            init_nodes.append(
                ET.fromstring(_retarget(sh["init"], d["name"], d.get("overrides"), enable_checks=False))
            )
        comp_nodes.append(
            ET.fromstring(_retarget(sh["comp"], d["name"], d.get("overrides"), enable_checks=enable_checks))
        )

    def _make_net():
        return ET.fromstring(
            '<NODE><NAME checkType="0" eclass="8" headNode="true" '
            'incorrectFeedback="" nodeValue="" obfuscateName="false" overrideDBGrading="false" '
            'variableEnabled="false" variableName="">Network</NAME><ID>Network</ID>'
            '<COMPONENTS></COMPONENTS><POINTS></POINTS></NODE>'
        )

    init_net = _make_net()
    for ch in init_nodes:
        init_net.append(ch)
    initialsetup = "<INITIALSETUP>\n %s\n <LOAD_INIT_TREE>true</LOAD_INIT_TREE>\n</INITIALSETUP>" % _format_scoring_tree(init_net)

    comp_net = _make_net()
    head_sc, tail_sc = [], []
    for sc_xml in shapes.get("scaffold", []):
        sc_el = ET.fromstring(sc_xml)
        nm = sc_el.findtext("NAME") or ""
        if nm in SCAFFOLD_TAIL:
            tail_sc.append(sc_el)
        else:
            head_sc.append(sc_el)
    for ch in head_sc + comp_nodes + tail_sc:
        comp_net.append(ch)
    if enable_checks:
        _propagate_check_types(comp_net)
    comparisons = "<COMPARISONS>\n %s\n</COMPARISONS>" % _format_scoring_tree(comp_net)

    if missing:
        import sys as _sys
        print("scoring: no shape for %s (not graded)" % sorted(set(missing)), file=_sys.stderr)
    return initialsetup, comparisons


build = from_shapes
