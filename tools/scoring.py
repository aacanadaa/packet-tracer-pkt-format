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


def _section(xml, tag):
    a = xml.find("<%s>" % tag)
    b = xml.find("</%s>" % tag, a) + len("</%s>" % tag)
    return xml[a:b]


def _net_node(root):
    return root.find("NODE")


def _device_nodes(net_node):
    """Direct child NODE elements of the Network node that are devices
    (heuristic: not one of the fixed scaffolding nodes)."""
    scaffold = {"Instruction", "Resource", "ConnectivityTests", "CodeTesting",
                "Remote Network", "Remote Networks", "Encircling Tests"}
    out = []
    for c in net_node:
        if c.tag == "NODE":
            nm = c.findtext("NAME") or ""
            if nm not in scaffold:
                out.append(c)
    return out


def from_template(template_xml, devices=None, overrides=None, rename=None):
    """Clone complete device nodes from a template activity.

    devices   : keep only these device names (default: all in the template)
    rename    : {old_name: new_name}
    overrides : {device_name: {item_id: value}} to set expected values
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
        devs = _device_nodes(net)
        # scaffolding = non-device direct children (COMPARISONS keeps them)
        kept = []
        if with_scaffold:
            for c in net:
                if c.tag == "NODE" and c not in devs:
                    kept.append(c)
        for d in devs:
            nm = d.findtext("NAME") or ""
            if devices is not None and nm not in devices:
                continue
            clone = ET.fromstring(ET.tostring(d))
            new = rename.get(nm, nm)
            for e in clone.iter("NAME"):
                if e.text == nm:
                    e.text = new
            for e in clone.iter("ID"):
                if e.text == nm:
                    e.text = new
            # apply value overrides by item id / label
            for e in clone.iter("NODE"):
                lbl = e.findtext("NAME")
                idn = e.findtext("ID")
                for key, val in overrides.get(new, {}).items():
                    if lbl == key or idn == key:
                        for nmel in e.iter("NAME"):
                            if nmel.text == lbl:
                                nmel.set("nodeValue", str(val))
            kept.append(clone)
        for c in list(net):
            net.remove(c)
        for c in kept:
            net.append(c)
        body = ET.tostring(net, encoding="unicode")
        if tag == "INITIALSETUP":
            return "<INITIALSETUP>%s<LOAD_INIT_TREE>true</LOAD_INIT_TREE></INITIALSETUP>" % body
        return "<COMPARISONS>%s</COMPARISONS>" % body

    return build("INITIALSETUP", with_scaffold=False), build("COMPARISONS", with_scaffold=True)


# --------------------------------------------------------------------------- #
# value derivation (from an answer network) -- use with from_template overrides
# --------------------------------------------------------------------------- #
def derive_values(answer_xml):
    """Return {device_name: {item_id: expected_value}} from a decoded answer
    network (IOS running-config + end-device port IPs)."""
    if isinstance(answer_xml, bytes):
        answer_xml = answer_xml.decode("utf-8", "replace")
    out = {}
    for m in re.finditer(r"<DEVICE>.*?</DEVICE>", answer_xml, re.S):
        blk = m.group(0)
        nm = re.search(r'<NAME[^>]*>([^<]*)</NAME>', blk)
        if not nm:
            continue
        name = nm.group(1)
        vals = {}
        model = re.search(r'<TYPE[^>]*model="([^"]*)"', blk)
        if model:
            vals["Device Model"] = model.group(1)
        rc = re.search(r"<RUNNINGCONFIG>(.*?)</RUNNINGCONFIG>", blk, re.S)
        if rc:
            for line in re.findall(r"<LINE>(.*?)</LINE>", rc.group(1), re.S):
                line = line.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
                ma = re.match(r"\s*ip address (\S+) (\S+)", line)
                if ma:
                    vals["IP Address"] = ma.group(1)
                    vals["Subnet Mask"] = ma.group(2)
                if re.match(r"\s*no shutdown", line):
                    vals["Port Up"] = "1"
        ip = re.search(r"<IP>([^<]*)</IP>", blk)
        gw = re.search(r"<PORT_GATEWAY>([^<]*)</PORT_GATEWAY>", blk)
        if ip and ip.group(1):
            vals["IP Address"] = ip.group(1)
        if gw and gw.group(1):
            vals["Default Gateway"] = gw.group(1)
        out[name] = vals
    return out


# --------------------------------------------------------------------------- #
# device-node "shape" library  (complete item nodes harvested from activities)
# --------------------------------------------------------------------------- #
import json
import glob
import os as _os

SCAFFOLD_NAMES = {"Instruction", "Resource", "ConnectivityTests", "CodeTesting",
                  "Remote Network", "Remote Networks", "Encircling Tests"}


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
        except ET.ParseError:
            continue
        inet, cnet = init_root.find("NODE"), comp_root.find("NODE")
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
    open(path, "wb").write(gzip.compress(json.dumps(shapes).encode("utf-8"), 9))


def load_shapes(path):
    import gzip
    b = open(path, "rb").read()
    if b[:2] == b"\x1f\x8b":
        b = gzip.decompress(b)
    return json.loads(b)


def _retarget(node_xml, name, overrides):
    el = ET.fromstring(node_xml)
    old = el.findtext("NAME")
    for e in el.iter("NAME"):
        if e.text == old:
            e.text = name
    for e in el.iter("ID"):
        if e.text == old:
            e.text = name
    for e in el.iter("NODE"):
        lbl, idn = e.findtext("NAME"), e.findtext("ID")
        for key, val in (overrides or {}).items():
            if lbl == key or idn == key:
                for nmel in e.iter("NAME"):
                    if nmel.text == lbl:
                        nmel.set("nodeValue", str(val))
    return ET.tostring(el, encoding="unicode")


def from_shapes(spec, shapes):
    """Build (initialsetup_xml, comparisons_xml) from harvested shapes.

    spec: [{"name": "R9", "model": "2911", "overrides": {...}}, ...]
    """
    init_nodes, comp_nodes = [], []
    missing = []
    for d in spec:
        model = d["model"]
        if model not in shapes["models"]:
            missing.append(model)
            continue
        sh = shapes["models"][model]
        if sh.get("init"):
            init_nodes.append(_retarget(sh["init"], d["name"], d.get("overrides")))
        comp_nodes.append(_retarget(sh["comp"], d["name"], d.get("overrides")))
    net_open = ('<NODE><NAME checkType="0" eclass="8" headNode="true" '
                'incorrectFeedback="" nodeValue="" obfuscateName="false" overrideDBGrading="false" '
                'variableEnabled="false" variableName="">Network</NAME><ID>Network</ID>'
                '<COMPONENTS></COMPONENTS><POINTS></POINTS>')
    net_close = "</NODE>"
    initialsetup = ("<INITIALSETUP>%s%s%s<LOAD_INIT_TREE>true</LOAD_INIT_TREE></INITIALSETUP>"
                    % (net_open, "".join(init_nodes), net_close))
    comparisons = ("<COMPARISONS>%s%s%s%s</COMPARISONS>"
                   % (net_open, "".join(shapes.get("scaffold", [])), "".join(comp_nodes), net_close))
    if missing:
        import sys as _sys
        print("scoring: no shape for %s (not graded)" % sorted(set(missing)), file=_sys.stderr)
    return initialsetup, comparisons
