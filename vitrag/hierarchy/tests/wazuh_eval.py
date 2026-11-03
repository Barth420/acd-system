"""
wazuh_eval.py: a SMALL evaluator of the Wazuh rule/decoder subset used by vitrag/hierarchy/wazuh/*.xml.

It exists so a test can replay one log through the Wazuh rules and through the Python forwarder and compare rule ids without a
running Wazuh. It implements only: decoders (prematch + regex + order), rules with <decoded_as> / <match>, frequency children
via <if_matched_sid> + <same_srcip/>, first-match-wins over top-level rules in file order. It is NOT Wazuh: it checks that the
two rule sets in this repo agree, not that Wazuh's own engine behaves this way (e.g. whether `frequency="5"` fires on the 5th or
6th event is taken to be the 5th here).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

from rules import parse_ts


def _load(path: Path) -> ET.Element:
    return ET.fromstring("<root>" + re.sub(r"<!--.*?-->", "", path.read_text(), flags=re.S) + "</root>")


class Wazuh:
    def __init__(self, decoders: Path, rules: Path):
        self.decoders = []
        for d in _load(decoders).iter("decoder"):
            self.decoders.append({"name": d.get("name"), "prematch": re.compile(d.findtext("prematch")),
                                  "regex": re.compile(d.findtext("regex")), "order": [x.strip() for x in d.findtext("order").split(",")]})
        self.rules = []
        for r in _load(rules).iter("rule"):
            self.rules.append({"id": int(r.get("id")), "level": int(r.get("level")), "freq": int(r.get("frequency", 0)),
                               "tf": int(r.get("timeframe", 0)), "decoded_as": r.findtext("decoded_as"), "match": r.findtext("match"),
                               "parent": int(r.findtext("if_matched_sid")) if r.find("if_matched_sid") is not None else None,
                               "same_srcip": r.find("same_srcip") is not None})
        self.hist: dict[tuple[int, str], deque[float]] = defaultdict(deque)

    def decode(self, line: str) -> tuple[Optional[str], dict[str, str]]:
        for d in self.decoders:
            if d["prematch"].search(line):
                m = d["regex"].search(line)
                return d["name"], (dict(zip(d["order"], m.groups())) if m else {})
        return None, {}

    def event(self, logkey: str, line: str) -> Optional[int]:
        now = parse_ts(line) or 0.0
        name, fields = self.decode(line)
        srcip = fields.get("srcip")
        if srcip is None and logkey == "nginx/access.log":      # Wazuh's built-in web access decoder supplies srcip for these
            srcip = line.split(" ", 1)[0]
        base = None
        for r in self.rules:
            if r["parent"] is not None:
                continue
            if r["decoded_as"] and r["decoded_as"] != name:
                continue
            if r["match"] and not re.search(r["match"], line):
                continue
            base = r
            break
        if base is None or srcip is None:
            return None
        q = self.hist[(base["id"], srcip)]
        q.append(now)
        for child in self.rules:                                  # file order: 100712 is listed before 100711
            if child["parent"] == base["id"]:
                while q and q[0] < now - child["tf"]:
                    q.popleft()
                if len(q) >= child["freq"]:
                    return child["id"]
        return base["id"]
