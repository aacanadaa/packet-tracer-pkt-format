# Cisco Packet Tracer 9.0.1 Compatibility Guide

Empirical findings, root causes, and preventive checks established against **Cisco Packet Tracer 9.0.1 (`9.0.1.0858`)** while troubleshooting `.pka` activities and `.pkt` topologies end-to-end.

---

## 1. Adjacent `</NODE><NODE>` Truncation and Scaffold Ordering in Scoring Trees

* **Symptom:** In `<COMPARISONS>` and `<INITIALSETUP>`, sibling device `<NODE>` elements serialized without an intervening newline (`</NODE><NODE>`) cause PT 9.0.1 to stop loading the tree after the first device. All subsequent devices silently vanish from **Assessment Items**, shrinking the total point count. Additionally, placing `Remote Network` / `Remote Networks` or `Encircling Tests` before device nodes can disrupt tree display.
* **Root cause:** `xml.etree.ElementTree.tostring()` concatenates appended sibling `<NODE>` elements on one line (`</NODE><NODE>`), and also collapses empty tags (`<COMPONENTS />`, `<POINTS />`).
* **Fix & Safeguard:**
  * [`tools/scoring.py`](../tools/scoring.py) runs `_format_scoring_tree()` (`ET.indent(..., space=" ", level=1)` and expands `<COMPONENTS></COMPONENTS>` / `<POINTS></POINTS>`) in both `from_shapes()` and `from_template()`, and orders top-level children as `SCAFFOLD_HEAD` -> device nodes -> `SCAFFOLD_TAIL` (`{"Remote Network", "Remote Networks", "Encircling Tests"}`).
  * `pkt_core.audit.validate_lab()` emits a `fail` finding (**`scoring-adjacent-nodes`**) whenever `<COMPARISONS>` or `<INITIALSETUP>` contains `b"</NODE><NODE>"`.

---

## 2. `checkType` Semantics (`0`/`1`/`2`) and Path-Scoped Overrides

* **Symptom:** Leaving `checkType="0"` on cloned/retargeted leaf nodes—or forgetting to propagate `checkType="1"` up every ancestor container up to `<NAME ...>Network</NAME>`—causes PT 9.0.1 to open with `0/0` scored items and report a false `Completion: 100%`. Flat override keys (such as `"IP Address"` or `"Power"`) also collide across multiple interfaces or between device-level power and per-port `Power`.
* **Observed values in PT 9.0.1:**
  * `checkType="0"` — unchecked item / inactive container.
  * `checkType="1"` — enabled container ancestor (`Network`, device node, `Ports`, interface node).
  * `checkType="2"` — enabled leaf grading item.
* **Fix & Safeguard:**
  * `tools/scoring.py` sets `checkType="2"` on matched leaves (other than `Device Model`) in `_retarget(..., enable_checks=True)` (`from_shapes()` defaults `enable_checks=True`) and promotes ancestors to `checkType="1"` via `_propagate_check_types()`.
  * `derive_values()` emits path-scoped interface keys (`Ports/<iface>/IP Address`, `Ports/<iface>/Subnet Mask`, `Ports/<iface>/Port Up`, `Ports/<iface>/Dynamic Mode`), canonicalizes short IOS names (`Gig0/` -> `GigabitEthernet0/`, `Fa0/` -> `FastEthernet0/`, `Vl` -> `Vlan`, etc.), and guards `Power` so device power does not overwrite `Ports/*/Power`.
  * `pkt_core.grade.grade_lab()` evaluates explicit `<COMPARISONS>` leaves with `checkType > 0` directly (preserving `<COMPONENTS>` category labels via `ScoringNode.components`) instead of overriding them with diff heuristics.

---

## 3. Outdated IoT Device Templates (`"Update Devices?"`) and `&#xd;` Line Endings

* **Symptom:** Opening labs containing certain IoT devices exported from older Packet Tracer releases prompts *"Update Devices?"* dialogs on load in PT 9.0.1.
* **Root cause:** PT 9.0.1 checks embedded IoT `<TEMPLATE_CREATION_TIME>` timestamps and `<FILE_MANAGER>` script payloads against its built-in `.ptd` templates. Note that raw `.ptd` `<FILE_MANAGER>/<FILE>/<FILE_CONTENT>/<TEXT>` entries encode CRLF newlines using literal `&#xd;` XML character references; naive ElementTree re-serialization normalizes numeric character references.
* **Fix & Verification:**
  * Refreshed 11 IoT models (`Battery`, `CO Detector`, `Metal Sensor`, `Servo`, `Solar Panel`, `Sound Sensor`, `Street Lamp`, `Trip Wire`, `Water Level Monitor`, `Webcam`, `Wind Turbine`) in both [`tools/device_templates.json`](../tools/device_templates.json) and `src/pkt_core/data/device_templates.json` using `<FILE_MANAGER>` (preserving raw `&#xd;` entities) and `<TEMPLATE_CREATION_TIME>` from PT 9.0.1 `.ptd` templates.
  * Verified in live PT 9.0.1 with generated IoT topologies opening cleanly with zero `"Update Devices?"` prompts (`update_prompts=0`).

---

## 4. End-Device `Default Gateway` Graded from `<ENGINE><GATEWAY>`

* **Symptom:** On end devices (`PC-PT`, `Server-PT`, `Laptop-PT`), PT 9.0.1 grades **Default Gateway** strictly from `<ENGINE><GATEWAY>`, ignoring `<PORT><PORT_GATEWAY>`. If `<PORT_GATEWAY>` holds the gateway IP while `<ENGINE><GATEWAY>` is empty, `0.0.0.0`, or stale, PT 9.0.1 marks **Default Gateway** `Incorrect`.
* **Fix & Safeguard:**
  * `tools/scoring.derive_values()` prefers `<ENGINE><GATEWAY>` over `<PORT_GATEWAY>`.
  * `pkt_core.grade` follows PT 9.0.1 semantics: when `<ENGINE>` explicitly carries a `<GATEWAY>` element, empty/`0.0.0.0` values are not masked by `<PORT_GATEWAY>`.
  * `pkt_core.audit.validate_lab()` emits a `warn` finding (**`end-device-gateway-mismatch`**) on `pc`/`server`/`laptop` devices whenever `<PORT><PORT_GATEWAY>` is configured (`!= "0.0.0.0"`) and differs from `<ENGINE><GATEWAY>`.

---

## 5. Switchport `Dynamic Mode` Enum (`1` / `2` / `3`)

* **Observed grading values in PT 9.0.1:**
  * `"1"` — dynamic auto (unconfigured switch Ethernet port default).
  * `"2"` — static trunk (`switchport mode trunk`).
  * `"3"` — static access (`switchport mode access`).
* **Fix:** Updated both `tools/scoring.derive_values()` and `pkt_core.grade` to emit `"1"`/`"2"`/`"3"` (replacing earlier `0`/`1` assumptions).

---

## 6. `<RUNNINGCONFIG>` Stops Parsing at `<LINE>end</LINE>` & SVI `Port Up` Parity

* **Symptom:** IOS lines appended after `<LINE>end</LINE>` inside `<RUNNINGCONFIG>` (for example, scripted `router bgp ...` blocks appended below `end`) are ignored by Packet Tracer's IOS config loader, causing runtime and grading failures in PT 9.0.1 while naive full-config scans still match them.
* **SVI observation:** In live PT 9.0.1, a switch SVI (`interface VlanN`) with an IP address configured and no `shutdown` evaluates `Port Up` as `"1"` (`Correct`) even without an explicit `no shutdown` line.
* **Fix & Safeguard:**
  * Both `tools/scoring.derive_values()` and `pkt_core.grade` stop parsing `<RUNNINGCONFIG>` when encountering `end`.
  * `pkt_core.grade` also treats `Vlan*` SVIs with an IP and no `shutdown` as up (`Port Up == "1"`), and extracts additional IOS/security/routing items (`Service Password Encryption`, `AAA/New-model`, `NTP/*`, `SSH Server/SSH Server Version`, `OSPF/*/Router ID`, `OSPF/*/Auto Cost`, `BGP/*`, `VTP/Domain Name`, `STP/RSTP`).
  * `pkt_core.audit.validate_lab()` emits a `fail` finding (**`config-after-end`**) if any non-blank, non-`!` `<LINE>` follows `end` in `<RUNNINGCONFIG>`.

---

## 7. `<CLEAN_ACTIVITY>`, `<LOAD_INIT_TREE>`, and Activity State Hygiene

* **Behavior:** When `<INITIALSETUP>` parses cleanly (no `</NODE><NODE>` truncation), either `<CLEAN_ACTIVITY>true</CLEAN_ACTIVITY>` or `<LOAD_INIT_TREE>true</LOAD_INIT_TREE>` causes PT 9.0.1 to initialize the student workspace from embedded network block `[1]` (initial). Setting **both** to `false` opens the saved working state in block `[0]` (needed when opening pre-solved/in-progress `.pka` snapshots).
* **Additional hygiene when editing existing `.pka` templates:** Strip stale non-existent device entries from `<LOCKINGTREE>` and reset negative `<ACTIVITY COUNTDOWNLEFT>` values if present.
* **Tooling:** [`tools/activity.py`](../tools/activity.py) now provides `Activity.set_load_init_tree(flag)` alongside `Activity.set_clean_activity(flag)`.
