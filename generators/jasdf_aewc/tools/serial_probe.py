#!/usr/bin/env python3
"""Minimal serial-link probe: two 2911s + HWIC-2T, one serial cable.
Used to determine empirically what Packet Tracer needs for a serial line to
come up.  Variant A mimics this project's encoding (CLOCKRATEFLAG=false on DTE);
variant B mimics lab_api's default (CLOCKRATEFLAG=true on both ends)."""
import sys, xml.etree.ElementTree as ET
from pathlib import Path
TK = Path('/home/saoria/testing/packet-tracer-pkt-format')
sys.path.insert(0, str(TK)); sys.path.insert(0, str(TK / 'tools'))
import lab_api

def build(out, dte_flag_true):
    models, modules = lab_api.load_templates(str(TK / 'tools' / 'device_templates.json'))
    lab = lab_api.Lab(str(TK / 'tools' / 'network_seed.xml'), models, modules)
    lab.prune_seed_devices()
    cfg = lambda n, ip: ["hostname " + n, "interface Serial0/0/0",
                         f" ip address {ip} 255.255.255.252", " no shutdown",
                         "interface GigabitEthernet0/0", " no shutdown", "end"]
    a = lab.add_device("2911", "SER-A", 200, 200, install="HWIC-2T",
                       ios_config=cfg("SER-A", "10.9.9.1"))
    b = lab.add_device("2911", "SER-B", 600, 200, install="HWIC-2T",
                       ios_config=cfg("SER-B", "10.9.9.2"))
    lab.link(a, "Serial0/0/0", b, "Serial0/0/0", kind="serial", dce=a, clock=2000000)
    if dte_flag_true:
        for sid in (a, b):
            el = lab._els[sid]
            for p in el.iter("PORT"):
                if p.findtext("TYPE") == "eSmartSerial":
                    f = p.find("CLOCKRATEFLAG")
                    if f is not None:
                        f.text = "true"
    lab.save(str(out))
    print("wrote", out)

if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2] == "true")
