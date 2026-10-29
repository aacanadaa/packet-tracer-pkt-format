# Demo: a working lab generated without Packet Tracer

What this proves: a `.pkt` written by `Lab()` opens in **Packet Tracer 9.0.1**, the
IOS configs apply on load, OSPF forms between the routers, and a PC on one site can
ping a PC on the other. Packet Tracer never authored anything here — it only opened
the result.

## Reproduce

```console
$ pip install packet-tracer-pkt-format
$ python build_demo.py            # writes ospf_lab.pkt
```

Then open `ospf_lab.pkt` in Packet Tracer. Nothing else is required — the seed
document and the 137-model template library ship inside the package.

## The topology

```
       10.0.1.0/24        10.0.12.0/24        10.0.2.0/24
  PC1 ──── SW1 ──── R1 ═══════════════ R2 ──── SW2 ──── PC2
 .10              .1  Gi0/0      Gi0/1  Gi0/1      Gi0/0 .1        .10
```

Six devices, five links, no serial. `R1` and `R2` carry a full running-config:
interface addresses, `no shutdown`, and `router ospf 1` covering both connected
subnets. PCs are addressed through `pc_ip=(ip, mask, gateway)`.

## The beats

| # | Screenshot | What it shows |
| --- | --- | --- |
| 1 | `shots/cap-01-topology-opened.png` | The file opens; devices and cables drawn, nothing placed by hand |
| 2 | `shots/cap-02-ospf-and-routing.png` | `%OSPF-5-ADJCHG ... LOADING to FULL`, then `O 10.0.2.0/24 via 10.0.12.2` |
| 3 | `shots/cap-03-ping-end-to-end.png` | `ping 10.0.2.10` → `Reply ... TTL=126` (two router hops) |

`demo.gif` is the three captioned stills in sequence. It is a **storyboard**, not a
screen recording — if you want real motion, record the same three actions.

## Two bugs this demo found

Both are real, and both were invisible from the package's own tests.

### 1. `pc_ip` gateway never reached Packet Tracer — fixed

`add_device(pc_ip=...)` wrote the gateway to `<PORT><PORT_GATEWAY>`, but PT reads an
end device's default gateway from **`<ENGINE><GATEWAY>`**. The port element was
correct and ignored; the device-level element kept whatever the harvested template
had, which on the shipped PC template is `1.1.1.2`.

Symptom: `ipconfig` showed the right address and mask, a gateway belonging to no
network in the lab, and `ping` to the far site timed out. Before and after are in
`shots/03a-before-fix-gateway.png` and `shots/cap-03-ping-end-to-end.png`.

The fix writes both elements. **This is uncommitted and needs a test before it
ships.**

### 2. Serial links produce a file PT refuses to open — open

`lab.link(..., kind="serial", dce=...)` after `install="HWIC-2T"` generates a
container that PT 9.0.1 rejects with *"not compatible with this version"*. The same
topology without the serial link opens cleanly, and the committed
`corpus/samples/sample_lab.pkt` opens cleanly, so the fault is in what the serial
link writes, not in the codec.

Not yet diagnosed. Reproduce with the `ospf_lab.pkt` that used
`kind="serial"` — the current `build_demo.py` deliberately avoids serial.

## Capture setup, if you want to redo it

Packet Tracer 9.0.1 here runs as an extracted AppImage on a headless X server,
because FUSE is unavailable in WSL:

```console
$ Xvfb :99 -screen 0 1600x900x24 &
$ DISPLAY=:99 openbox &
$ DISPLAY=:99 LD_LIBRARY_PATH=/opt/pt/bin /opt/pt/bin/PacketTracer &
$ DISPLAY=:99 import -window root shot.png          # still
$ DISPLAY=:99 xdotool mousemove X Y click 1         # drive it
```

Login goes through Cisco SSO in a browser; PT listens on `127.0.0.1:8001` for the
callback, so a browser inside the same Linux namespace completes the flow with no
port forwarding.

One caveat for automated capture: the device window needs the *window activated*
before synthetic double-clicks register. `xdotool windowactivate --sync` first, or
the clicks land on the canvas and nothing opens.
