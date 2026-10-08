#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
make_scored_lab.py -- build a complete, scored Packet Tracer activity (`.pka`)
entirely offline, from the shipped skeletons:

    tools/network_seed.xml       network seed (physical scene + reusable devices)
    tools/device_templates.json  device/module templates (base64)
    tools/device_shapes.json     scoring device-node shapes
    tools/activity_skeleton.xml  activity wrapper skeleton

No Packet Tracer and no external sample files are needed.  The result opens in
PT as an activity with instructions, a password, permissions, an initial and an
answer network, and a scoring tree.
"""
import argparse
import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import build_configured_lab as B   # proven network builder  # noqa: E402
import activity                    # noqa: E402
import scoring                     # noqa: E402
import pt9                         # noqa: E402

R_CFG = ["!", "version 15.1", "no service timestamps log datetime msec",
         "no service timestamps debug datetime msec", "service password-encryption", "!",
         "hostname R9", "!", "ip cef", "no ipv6 cef", "!",
         "interface GigabitEthernet0/0", " ip address 192.168.9.1 255.255.255.0", " no shutdown", "!",
         "end"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="scored_lab.pka")
    ap.add_argument("--password", default="")
    ap.add_argument("--instructions",
                    default="<h3>Task</h3><p>Configure R9 GigabitEthernet0/0 = 192.168.9.1/24 and "
                            "PC9 = 192.168.9.10, gateway 192.168.9.1.</p>")
    a = ap.parse_args()

    tpl = json.load(open(os.path.join(HERE, "device_templates.json")))
    models = {k: base64.b64decode(v) for k, v in tpl["models"].items()}
    shapes = scoring.load_shapes(os.path.join(HERE, "device_shapes.json"))
    seed = os.path.join(HERE, "network_seed.xml")

    def build(path, configured):
        b = B.Builder(seed, models)
        r, re_ = b.device("2911", "R9", 250, 350)
        sw, swe = b.device("2960-24TT", "SW9", 450, 350)
        pc, pce = b.device("PC-PT", "PC9", 650, 350)
        if configured:
            b.run_config(re_, R_CFG)
            b.pc_ip(pce, "192.168.9.10", "255.255.255.0", "192.168.9.1")
        b.link(r, "GigabitEthernet0/0", sw, "GigabitEthernet0/1")
        b.link(sw, "FastEthernet0/1", pc, "FastEthernet0")
        b.save(path)

    build("/tmp/_pt9_initial.pkt", False)
    build("/tmp/_pt9_answer.pkt", True)
    initial = pt9.decode("/tmp/_pt9_initial.pkt", "pkt").decode("utf-8")
    answer = pt9.decode("/tmp/_pt9_answer.pkt", "pkt").decode("utf-8")

    vals = scoring.derive_values(answer)
    spec = [{"name": n, "model": m, "overrides": vals.get(n, {})}
            for n, m in (("R9", "2911"), ("SW9", "2960-24TT"), ("PC9", "PC-PT"))]
    init_sc, comp_sc = scoring.from_shapes(spec, shapes)

    act = activity.Activity(os.path.join(HERE, "activity_skeleton.xml"))
    act.set_instructions([a.instructions])
    act.set_password(a.password)
    act.set_permissions(locked=False, noguest=False, component_list="Ip, Physical, Other")
    act.set_feedback(incomplete="Keep going.", complete="Lab complete - well done!")
    act.set_scoring_xml(init_sc, comp_sc)
    act.set_networks(initial_xml=initial, answer_xml=answer)
    act.save(a.out)
    print(f"wrote {a.out} ({len(open(a.out,'rb').read())} bytes)")


if __name__ == "__main__":
    main()
