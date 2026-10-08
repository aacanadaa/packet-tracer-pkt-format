#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 aacanadaa
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""
activity.py -- author Packet Tracer *activity* files (`.pka`) programmatically:
instructions, activity password, permissions, feedback, and the initial / answer
networks.  Built on the pt9 codec.  Reverse-engineered from PT 9.0.1; see
../docs/ACTIVITY.md.

    from activity import Activity
    a = Activity("template.pka")
    a.set_instructions(["<h3>Task</h3><p>Configure R1…</p>"])
    a.set_password("hunter2")
    a.set_permissions(locked=True, noguest=True, components="Ip, Routing, Acl")
    a.set_networks(initial_xml=open("start.xml","rb").read(), answer_xml=open("done.xml","rb").read())
    a.save("mylab.pka")

The `.pka` root is `<PACKETTRACER5_ACTIVITY>` and embeds **three** `<PACKETTRACER5>`
documents: [0] working/current, [1] initial network, [2] answer network.
"""
import re

import pt9

PKT = re.compile(r"<PACKETTRACER5>.*?</PACKETTRACER5>", re.S)


class Activity:
    def __init__(self, template):
        raw = open(template, "rb").read()
        if template.lower().endswith((".pka", ".pkt")):
            raw = pt9.decode_bytes(raw, "pkt")
        self.xml = raw.decode("utf-8")
        if "<PACKETTRACER5_ACTIVITY>" not in self.xml:
            raise ValueError("template is not an activity (no <PACKETTRACER5_ACTIVITY>)")
        if len(PKT.findall(self.xml)) < 3:
            raise ValueError("activity does not embed 3 networks")

    # ---- rewriting helpers -------------------------------------------------
    def _set_attr(self, tag, name, value):
        m = re.search(r"<%s\b[^>]*>" % tag, self.xml)
        if not m:
            return
        el = m.group(0)
        if re.search(r'\b%s="[^"]*"' % name, el):
            el = re.sub(r'\b%s="[^"]*"' % name, '%s="%s"' % (name, value), el)
        else:
            el = el[:-1] + ' %s="%s">' % (name, value)
        self.xml = self.xml[:m.start()] + el + self.xml[m.end():]

    def _set_text(self, tag, value):
        self.xml = re.sub(r"<%s(?:\s[^>]*)?>.*?</%s>" % (tag, tag),
                          "<%s>%s</%s>" % (tag, value, tag), self.xml, count=1, flags=re.S)

    # ---- public API --------------------------------------------------------
    def set_instructions(self, pages, enable_tab=False, layout=0, title=""):
        """pages: list of HTML strings (or a single string)."""
        if isinstance(pages, str):
            pages = [pages]
        body = "".join(
            '<PAGE translate="true" tabify="%d" title="%s"><![CDATA[%s]]></PAGE>'
            % (i, title, html) for i, html in enumerate(pages))
        new = '<INSTRUCTIONS enable_tab="%s" layout="%d">%s</INSTRUCTIONS>' % (
            "true" if enable_tab else "false", layout, body)
        self.xml = re.sub(r"<INSTRUCTIONS\b[^>]*>.*?</INSTRUCTIONS>", new,
                          self.xml, count=1, flags=re.S)

    def set_password(self, password):
        """Activity-Wizard password (ACTIVITY/@PASS)."""
        self._set_attr("ACTIVITY", "PASS", password)

    def set_timer(self, enabled=True, seconds=0):
        """Countdown timer: ENABLED yes/no, COUNTDOWNMS/TIMERTYPE."""
        self._set_attr("ACTIVITY", "ENABLED", "yes" if enabled else "no")
        self._set_attr("ACTIVITY", "TIMERTYPE", "1" if seconds else "0")
        self._set_attr("ACTIVITY", "COUNTDOWNMS", str(int(seconds) * 1000))

    def set_permissions(self, locked=None, noguest=None, component_list=None,
                        locking_enabled=None):
        """USER_PROFILE_LOCKED / USER_PROFILE_NOGUEST / COMPONENT_LIST / LOCKINGTREE."""
        if locked is not None:
            self._set_text("USER_PROFILE_LOCKED", "true" if locked else "false")
        if noguest is not None:
            self._set_text("USER_PROFILE_NOGUEST", "true" if noguest else "false")
        if component_list is not None:
            self._set_text("COMPONENT_LIST", component_list)
        if locking_enabled is not None:
            self._set_attr("LOCKINGTREE", "enabled", "yes" if locking_enabled else "no")

    def set_feedback(self, incomplete=None, complete=None):
        if incomplete is not None:
            self._set_text("OVERALL_INCOMPLETE_FEEDBACK", incomplete)
        if complete is not None:
            self._set_text("OVERALL_COMPLETE_FEEDBACK", complete)

    def set_unlock_percent(self, percent):
        self._set_text("UNLOCK_ASSESSMENT_ITEM_PERCENT", str(int(percent)))

    def set_clean_activity(self, flag):
        self._set_text("CLEAN_ACTIVITY", "true" if flag else "false")

    def set_scoring_xml(self, initialsetup_xml, comparisons_xml):
        self.xml = re.sub(r"<INITIALSETUP>.*?</INITIALSETUP>", initialsetup_xml,
                          self.xml, count=1, flags=re.S)
        self.xml = re.sub(r"<COMPARISONS>.*?</COMPARISONS>", comparisons_xml,
                          self.xml, count=1, flags=re.S)

    def set_scoring(self, spec):
        """spec: list of device dicts, or an answer-network XML to derive from."""
        import scoring
        if isinstance(spec, (str, bytes)):
            spec = scoring.derive_from_network(spec)
        init, comp = scoring.build(spec)
        self.set_scoring_xml(init, comp)

    def set_networks(self, initial_xml=None, answer_xml=None):
        """Replace the initial (block 1) and answer (block 2) networks.
        Each value is full `<PACKETTRACER5>…</PACKETTRACER5>` XML (bytes or str),
        e.g. produced by pt9.decode(some.pkt).  Block 0 (current) is set to the
        same as initial, matching how PT saves a fresh activity."""
        blocks = list(PKT.finditer(self.xml))
        if initial_xml is not None:
            if isinstance(initial_xml, bytes):
                initial_xml = initial_xml.decode("utf-8")
            # block 0 and block 1 := initial
            for idx in (1, 0):
                b = blocks[idx]
                self.xml = self.xml[:b.start()] + initial_xml + self.xml[b.end():]
                blocks = list(PKT.finditer(self.xml))
        if answer_xml is not None:
            if isinstance(answer_xml, bytes):
                answer_xml = answer_xml.decode("utf-8")
            b = blocks[2]
            self.xml = self.xml[:b.start()] + answer_xml + self.xml[b.end():]

    def save(self, path):
        pt9.encode(path, self.xml.encode("utf-8"), "pkt")


if __name__ == "__main__":
    import sys
    print("activity.py: import Activity. See docs/ACTIVITY.md")
