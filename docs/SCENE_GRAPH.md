# Scene graph, device layout and cable binding

Notes from generating large Packet Tracer files programmatically.  Read together
with [../FORMAT.md](../FORMAT.md), which covers the container/crypto.  Here we
cover what is *inside* the XML and what Packet Tracer validates on load.

## 1. Document shape

```
<PACKETTRACER5>
  <VERSION>9.0.1.0858</VERSION>
  <PIXMAPBANK>…</PIXMAPBANK>
  <MOVIEBANK>…</MOVIEBANK>
  <NETWORK>
    <DEVICES>   <DEVICE>…</DEVICE> …   </DEVICES>
    <LINKS>     <LINK>…</LINK>   …     </LINKS>
    <SHAPETESTS/>
    <DESCRIPTION/>
  </NETWORK>
  <SCENARIOSET>…</SCENARIOSET>
  <OPTIONS>…</OPTIONS>
  <PHYSICALWORKSPACE>…</PHYSICALWORKSPACE>   <!-- the "Physical" tab scene -->
  <FILTERS/> <CLUSTERS>…</CLUSTERS> <LINES/> <RECTANGLES/> … 
  <USER_PROFILE/> <MULTITUSER/> <GEOVIEW_GRAPHICSITEMS/> …
</PACKETTRACER5>
```

Each `<DEVICE>` carries its own identity and placement:

* `<SAVE_REF_ID>save-ref-id:NNNN</SAVE_REF_ID>` — unique device id used by links.
* `<WORKSPACE><LOGICAL><X>/<Y>` — position on the logical canvas.
* `<WORKSPACE><LOGICAL><MEM_ADDR>/<DEV_ADDR>` — runtime heap pointers (see §3).
* `<WORKSPACE><PHYSICAL>…</PHYSICAL>` — a path into the physical workspace.

## 2. The physical workspace

`<PHYSICALWORKSPACE>` is a tree of `<NODE>`s (Intercity → Home City → Building →
Wiring Closet → Rack → device).  Each node ends with
`<UUID_STR>{guid}</UUID_STR>`.  A device's `<PHYSICAL>` value is a comma-joined
path of node GUIDs ending at that device's own leaf node, e.g.

```
{intercity},{city},{building},{closet},{rack},{deviceleaf}
```

`<PHYSICAL_CPUR>` mirrors part of it (`<PARENT_PATH>` = path to the closet,
`<CONTAINER_ID>` = the rack GUID, plus the rack slot `<X>`).  The leaf `<NODE>`
under the rack has the same GUID as the last path element, the device's name,
and the same slot `<X>`.

### Merging devices from different files

Devices harvested from *other* `.pkt` files carry physical paths that reference
nodes which do not exist in the destination file, so Packet Tracer rejects the
file with **"corrupted Physical Workspace data"**.

Two rules make a merge load:

1. Repoint every merged device to a physical node that **already exists** in the
   seed's `<PHYSICALWORKSPACE>` (reuse one valid path, including its leaf GUID,
   for the merged devices).  Orphan extra nodes are tolerated.
2. Normalise the element: some files store a *name path* with an attribute,
   e.g. `<PHYSICAL translate="true">Intercity,Home City,…,Rack,Router0</PHYSICAL>`.
   Rewriting the text to GUIDs but leaving `translate="true"` corrupts it —
   drop the attribute (`<PHYSICAL>`).

With those, a canvas of 144 devices / 140 distinct models (harvested from the
~293 sample labs shipped with PT) opens correctly.  See
[tools/harvest_merge.py](../tools/harvest_merge.py).

## 3. How cables actually bind

A `<LINK>` looks like:

```xml
<LINK><TYPE>eCopper</TYPE><CABLE>
  <LENGTH>1</LENGTH><FUNCTIONAL>true</FUNCTIONAL>
  <FROM>save-ref-id:…</FROM><PORT>GigabitEthernet0/2</PORT>
  <TO>save-ref-id:…</TO><PORT>FastEthernet0</PORT>
  <FROM_DEVICE_MEM_ADDR>…</FROM_DEVICE_MEM_ADDR>
  <TO_DEVICE_MEM_ADDR>…</TO_DEVICE_MEM_ADDR>
  <FROM_PORT_MEM_ADDR>…</FROM_PORT_MEM_ADDR>
  <TO_PORT_MEM_ADDR>…</TO_PORT_MEM_ADDR>
  <GEO_VIEW_COLOR>#6ba72e</GEO_VIEW_COLOR>
  <IS_MANAGED_IN_RACK_VIEW>false</IS_MANAGED_IN_RACK_VIEW>
  <TYPE>eStraightThrough</TYPE>
</CABLE></LINK>
```

The `*_MEM_ADDR` values are heap pointers, but despite appearances **they are
not what PT validates**: overwriting `FROM_PORT_MEM_ADDR` with `1` in a valid
file still loads.  Packet Tracer rebinds every cable from the logical ids.  What
must hold:

1. `<FROM>`/`<TO>` must equal an `<ENGINE><SAVE_REF_ID>` that exists in
   `<DEVICES>`.  Devices harvested from other files often have **no**
   `SAVE_REF_ID` element; it must be added (inside `<ENGINE>`) and referenced.
2. `<PORT>` must name an interface that exists on **that exact device
   instance** — modules differ between instances of the same model, so the port
   name has to be harvested together with the device block, not guessed from the
   model.
3. A matching `<TYPE>eCopper</TYPE>` / cable `<TYPE>eStraightThrough</TYPE>`.

Satisfying those, cables can be synthesised entirely offline.  With this repo,
`tools/build_wired_lab.py` produces a 147-device / 140-model lab with a
switch backbone and **71 cables** that Packet Tracer opens and draws.

(Previous experiments that failed with *"corrupted Physical Workspace data"* were
the scene-placement bug of §2; failures with *"not compatible with this
version"* were missing `SAVE_REF_ID` / a bad port name.)

## 4. Other observations

* `<CLUSTERS>` in a simple file is just the root logical cluster (`1-1`); devices
  reference it through `<DEVCLUSTERID>`.
* Devices from older labs may trigger an informational *"N device(s) that have
  outdated run-time scripts"* dialog on load — harmless.
* `<PIXMAPBANK>`/`<MOVIEBANK>` are often empty for model-icon devices; PT uses
  built-in art, so an empty bank is fine.
