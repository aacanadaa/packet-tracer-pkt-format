# JASDF AEW&C Enterprise — JADGE Network Model

A large, fully-configured Cisco Packet Tracer model of a Japan Air Self-Defense
Force (JASDF) Airborne Early Warning & Control (AEW&C / AWACS) enterprise,
generated entirely from code.

| | |
| --- | --- |
| **Deliverable** | `out/JASDF_AEWC_JADGE.pkt` — 290 devices, 326 links, 1.13 MB |
| **Profiles** | `smoke` (134) · `standard` · `enterprise` (290) |
| **Routing** | OSPF multi-area (area 0 backbone + per-site stub areas), iBGP AS65001, eBGP AS65002 |
| **Configuration** | 205 devices carry a full IOS/ASA running-config — 22,579 lines |
| **Services** | 496 DNS A-records · 259 DHCP pools · 202 RADIUS clients · NTP · syslog · SNMPv2c · TFTP · HTTPS · PKI · NetFlow |
| **Verified** | byte-exact container round-trip, every cabled port attested, **opens in Packet Tracer 9.0.1 with no load errors** |

![Verified in Packet Tracer 9.0.1](docs/img/packet_tracer_verified.png)

*Packet Tracer 9.0.1 with the generated lab open — green link indicators
throughout, serial datalink bearers up (drawn red by PT's serial cable style).*

---

## Architecture at a glance

![Topology](docs/img/topology_overview.png)

Thirteen operational tiers, modelled on the real JASDF air-defence system:

| Tier | Devices | What it models |
| --- | ---: | --- |
| AEW&C airborne platforms | 74 | 4× E-767 AWACS, 6× E-2D, 4× E-2C, 2× RC-2 — each a flying LAN |
| Fixed radar sites | 56 | 16 named J/FPS-3/-5/-7 sites from Wakkanai to Yonaguni |
| Air bases | 60 | 10 bases with distribution/access switching and WLAN |
| Control & Reporting Centers | 32 | Misawa, Iruma, Kasuga, Naha — dual C2 routers + HSRP |
| JADGE core data centre | 25 | 21-service server farm behind a firewall |
| Tactical datalink / SATCOM | 10 | Link-16 and X/Ku-band ground-entry serial concentrators |
| Air Defense Command HQ | 9 | Yokota AB — commander, ops, intel, liaison, COP |
| NOSC management enclave | 6 | jump host, NMS, cyber observer, packet tap |
| JADGE backbone transport | 6 | dual collapsed core + core routers + WAN edges |
| Security appliances | 4 | ASA 5505 zone firewalls |
| Regional WAN aggregation | 4 | NORTH / CENTRAL / WEST / SW hubs |
| Coalition partner | 4 | allied AS65002 boundary with IPsec |
| | **290** | |

Full detail: **[docs/DESIGN.md](docs/DESIGN.md)**.

---

## Quick start

```console
$ git clone https://github.com/aacanadaa/packet-tracer-pkt-format.git
$ cd packet-tracer-pkt-format && python3 -m venv .venv && . .venv/bin/activate
$ pip install -e . pytest pydantic

$ cd /path/to/jasdf-aewc
$ python build_jasdf_aewc.py --profile enterprise --out out/JASDF_AEWC_JADGE.pkt
$ python validate.py out/JASDF_AEWC_JADGE.pkt
$ python tools/draw_topology.py out/JASDF_AEWC_JADGE.pkt docs/img/topology.svg
$ python tools/export_plan.py out/JASDF_AEWC_JADGE.pkt
```

Then open `out/JASDF_AEWC_JADGE.pkt` in Packet Tracer 9.x.

> **First-open note.** Packet Tracer runs spanning-tree convergence after loading
> a file with many switches, so some access ports show *amber* link lights for
> the first ~30 s. This is documented Cisco behaviour, not a fault. Toggling
> between Realtime and Simulation mode 3–4 times clears it immediately.

---

## Repository layout

```
build_jasdf_aewc.py        topology generator + CLI (the model itself)
jasdf_kit.py               IOS / ASA running-config generators and
                           Server-PT service injection
validate.py                structural + evidence validation of a built .pkt
tools/
  build_port_model.py      derives allowed port names per model from evidence
  draw_topology.py         renders the tier-coloured architecture diagram
  export_plan.py           as-built address plan, subnets, VLANs, services
  mine_corpus.py           mines the reference corpus for port/config evidence
  serial_probe.py          minimal 2-router serial-link probe
  stp_probe.py             isolates STP/portfast behaviour per option
docs/
  DESIGN.md                full architecture specification
  VALIDATION.md            what was checked, how, and what it proves
  EVIDENCE.md              where every format/port/config fact came from
  INVENTORY_enterprise.csv every device with role and management address
  ADDRESS_PLAN.csv         622 addressed interfaces
  SUBNETS.csv              335 subnets
  VLANS.csv                the VLAN plan
  SERVICES.md              DNS zone, DHCP pools, AAA clients
  img/                     topology diagram + Packet Tracer screenshots
out/
  JASDF_AEWC_JADGE.pkt     the deliverable
```

---

## Scale profiles

```console
$ python build_jasdf_aewc.py --profile smoke      # 134 devices — fast iteration
$ python build_jasdf_aewc.py --profile standard   # regional subset
$ python build_jasdf_aewc.py --profile enterprise # 290 devices (default)
```

| Profile | AWACS | E-2D | E-2C | RC-2 | Radar | Air bases | Consoles |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| smoke | 1 | 1 | 1 | 0 | 4 | 3 | 1 |
| standard | 2 | 3 | 2 | 1 | 10 | 6 | 2 |
| enterprise | 4 | 6 | 4 | 2 | 16 | 10 | 3 |

---

## Licence

The generator in this repository is released under PolyForm Noncommercial
1.0.0, matching the toolchain it builds on. It depends on
[packet-tracer-pkt-format](https://github.com/aacanadaa/packet-tracer-pkt-format);
the generated `.pkt` is your own artefact.
