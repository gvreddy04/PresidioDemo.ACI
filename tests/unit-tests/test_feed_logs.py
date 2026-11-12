"""Verify the before/after transaction log, the detection log blocks and the harness detection summary."""
import json
from pathlib import Path
import re
import struct
import subprocess
import unittest

from pipeline_harness import PROJECT, run

SPIKE = PROJECT / "tests" / "DetectionParityChecks" / "bin" / "Debug" / "net10.0" / "DetectionParityChecks.dll"
HEADER = re.compile(r"^(\S+) ([0-9a-f]{32}) DETECTION (PUBLISHED|DEAD-LETTERED) strings=(\d+) pii=(\d+) non-pii=(\d+) review=(\d+)"
                    r"( offsets=payload)?( reason=(\".*\"))?$")
TAIL = re.compile(r"  format=(\S+) entity=(\S+) score=(\d\.\d\d) "
                  r"decision=(masked|replaced|kept|masked-inside|anchor|masked-by-default|missed-below-threshold)$")
GROUPS = {"  PII fields (changed)": "pii", "  Non-PII fields (unchanged)": "non-pii", "  Review (a format or keep may be needed)": "review"}
DECISIONS = {"pii": {"masked", "replaced", "masked-inside"}, "non-pii": {"kept", "anchor"},
             "review": {"masked-by-default", "missed-below-threshold"}}
BINARY = ("ACI", "ETKT", "PNR")


def payload_of(content):
    """The decoded payload of an MQ export (.txt) or a raw payload (.bin)."""
    text = content.decode("utf-8", errors="replace")
    rows = [line[2:].strip() for line in text.splitlines() if line.startswith("X ")]
    return bytes.fromhex("".join(rows)) if rows else content


def sample_values():
    """Every decoded value of the supplied samples: XDR counted strings and JSON scalars."""
    values = set()
    for path in sorted((PROJECT / "docs" / "sample-docs").rglob("*.txt")):
        payload = payload_of(path.read_bytes())
        if path.parent.name in BINARY:
            offset = 0
            while offset + 4 <= len(payload):
                length = struct.unpack(">I", payload[offset:offset + 4])[0]
                end = offset + 4 + length
                if 0 < length <= len(payload) - offset - 4 and all(0x20 <= b <= 0x7E for b in payload[offset + 4:end]):
                    values.add(payload[offset + 4:end].decode("ascii"))
                    offset = end + (-length % 4)
                else:
                    offset += 4
        else:
            stack = [json.loads(payload.decode("utf-8", errors="replace"))]
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
                elif item is not None:
                    values.add(str(item))
    return values


def shape(value):
    """The detection-log shape of a value: A for a letter, 9 for a digit, other characters unchanged."""
    return re.sub(r"[0-9]", "9", re.sub(r"[A-Za-z]", "A", value))


def declared_keys():
    """JSON property names declared in the recognizer files; value-free pointers print only these (WR-018)."""
    import xml.etree.ElementTree as ET
    folder = PROJECT / "src" / "PresidioDemo.Core" / "Configuration" / "recognizers"
    return {key.text.strip() for path in folder.glob("*.xml") for key in ET.parse(path).getroot().iter("key")}


def leaked_values(text):
    """Sample values of 4+ characters found in text, except values identical to their own shape (such as 9999).
    Declared names in value-free pointers are labels from the recognizer files and are removed before the search;
    every other pointer segment stays, so a value used as a property name would be found."""
    declared = declared_keys()

    def scrub(match):
        return " ".join(s for s in match.group(0).split("/") if s and s != "?" and not s.isdigit() and s not in declared)

    text = re.sub(r"(?<=    )/\S*", scrub, text)
    return sorted(v for v in sample_values() if len(v.strip()) >= 4 and shape(v.strip()) != v.strip() and v.strip() in text)


def blocks(text):
    """Every detection block in console text: its header match, its lines, and its entries as (group, line)."""
    found, current, group = [], None, None
    for line in text.splitlines():
        header = HEADER.match(line)
        if header:
            current, group = {"header": header, "lines": [line], "entries": []}, None
            found.append(current)
        elif current is not None and line.startswith("  "):
            current["lines"].append(line)
            if line in GROUPS:
                group = GROUPS[line]
            elif line != "    (none)":
                current["entries"].append((group, line))
        else:
            current = None
    return found


def location(line):
    """The location column of an entry: a binary slot and offset, a value-free pointer, or a JSON-encoded pointer."""
    body = line[4:]
    if body.startswith("slot "):
        return re.match(r"slot \d+ @0x[0-9A-F]+", body).group(0)
    if body.startswith('"'):
        return json.JSONDecoder().raw_decode(body)[0]
    return body.split(" ", 1)[0]


def values_of(line):
    """The JSON-encoded before and after values of a values-mode entry; after is None when unchanged or not published."""
    body = line[4:]
    if body.startswith('"'):
        _, end = json.JSONDecoder().raw_decode(body)
        body = body[end:]
    elif body.startswith("slot "):
        body = body[re.match(r"slot \d+ @0x[0-9A-F]+", body).end():]
    body = body.lstrip()
    before, end = json.JSONDecoder().raw_decode(body)
    rest = body[end:]
    if rest.startswith(" -> \""):
        after, _ = json.JSONDecoder().raw_decode(rest[4:])
        return before, after
    return before, None


def detection_log(state):
    run_ = subprocess.run(["dotnet", str(SPIKE), "detection-log", state], capture_output=True, text=True, timeout=900)
    if run_.returncode != 0:
        raise AssertionError("Build tests/DetectionParityChecks first: " + run_.stdout + run_.stderr)
    return run_.stdout


class DetectionLogTests(unittest.TestCase):
    """V-05: with the switch on, one value-free block per message listing every decoded string once; off, none (WR-018)."""

    @classmethod
    def setUpClass(cls):
        cls.on = detection_log("on")
        cls.off = detection_log("off")

    def test_every_decoded_string_is_listed_once_in_its_group(self):
        expected = sum(int(m.group(1)) for m in re.finditer(r"^SAMPLE \S+ candidates=(\d+)", self.on, re.M))
        found = blocks(self.on)
        self.assertGreater(expected, 0)
        self.assertEqual(sum(len(b["entries"]) for b in found), expected)
        for block in found:
            header = block["header"]
            entries = block["entries"]
            self.assertEqual(int(header.group(4)), len(entries))
            for group, index in (("pii", 5), ("non-pii", 6), ("review", 7)):
                self.assertEqual(int(header.group(index)), sum(1 for g, _ in entries if g == group))
            self.assertEqual(header.group(8) is not None, header.group(1) in BINARY, "offset base only for binary feeds")
            for group, line in entries:
                tail = TAIL.search(line)
                self.assertIsNotNone(tail, "an entry ends with format, entity, score and decision")
                self.assertIn(tail.group(4), DECISIONS[group], "a decision is listed in its own group")

    def test_no_sample_value_appears_in_the_log(self):
        text = "\n".join("\n".join(b["lines"][1:]) for b in blocks(self.on))
        leaked = leaked_values(text)
        self.assertEqual(leaked, [], "values found in the detection log: " + str(len(leaked)))

    def test_switched_off_writes_no_detection_blocks(self):
        self.assertNotIn(" DETECTION ", self.off)
        self.assertIn("SAMPLE ", self.off)


class FeedLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (PROJECT / "tests/unit-tests/fixtures/seats-mq-export.txt").read_bytes()
        cls.harness = run({"Seats/comparison.txt": cls.original}, expect=0, prefix="feed-logs-")
        cls.addClassCleanup(cls.harness.cleanup)

    def test_one_log_per_transaction_with_complete_before_and_after_sections(self):
        original = self.original
        item = self.harness.item("Seats", "comparison.txt")
        logs = list((self.harness.output_root / "logs").rglob("*"))
        self.assertEqual([p.name for p in logs if p.is_file()], ["comparison.txt.log.txt"])
        text = self.harness.log("Seats", "comparison.txt")
        self.assertIn("Transaction: " + item["MessageId"], text)
        self.assertEqual(text.count("BEFORE ANONYMIZATION"), 1)
        before, after = text.split("AFTER ANONYMIZATION")
        self.assertIn("BEFORE ANONYMIZATION", before)
        self.assertIn(original.decode("utf-8"), before)
        self.assertIn("Decoded MQ payload", before)
        self.assertIn("Decoded MQ payload", after)
        self.assertIn("Complete feed data (" + str(len(original)) + " bytes):", before)
        self.assertNotIn("Parsed fields", text, "the detection block replaces the parsed field list")
        self.assertNotIn("DETECTION", after)
        self.assertNotIn("Plain text:", after)
        self.assertLess(before.index("Complete feed data"), before.index("Decoded MQ payload"))
        self.assertLess(before.index("Decoded MQ payload"), before.index("Plain text:"))
        self.assertLess(before.index("Plain text:"), before.index("Detection ("))
        self.assertIn(item["MessageId"] + " DETECTION PUBLISHED", before)
        output = self.harness.published("Seats", "comparison.txt")
        self.assertLess(after.index("Decoded MQ payload"), after.index("Complete feed data"))
        self.assertIn("Complete feed data (" + str(len(output)) + " bytes):", after)
        self.assertIn(output.decode("utf-8"), after)

    def test_the_file_block_carries_values(self):
        found = blocks(self.harness.log("Seats", "comparison.txt"))
        self.assertEqual(len(found), 1)
        self.assertTrue(all(values_of(line)[0] is not None for _, line in found[0]["entries"]))


class DetectionLogValuesTests(unittest.TestCase):
    """WR-020: --detection-log values (as Presidio:DetectionLogValues) adds before and after values and full pointers to
    every entry; nothing else changes.

    Assertion messages name samples and counts only, never a value."""

    NOTE = "LINE ONE\nSAY \"HI\" \\ X"  # fictional, with a newline, quotes and a backslash
    ODD_KEY = "Odd\nKey"  # fictional property name with a newline, to show it cannot break a summary line

    @classmethod
    def setUpClass(cls):
        samples = PROJECT / "docs" / "sample-docs"
        inputs = {f"{p.parent.name}/{p.name}": p.read_bytes() for p in sorted(samples.rglob("*.txt"))}
        linking = json.loads(payload_of((samples / "PNR-Linking" / "PNR_LINKING.txt").read_bytes()))
        linking[0]["NewContactNote"] = cls.NOTE
        linking[0][cls.ODD_KEY] = "MADE UP REMARK"
        inputs["PNR-Linking/values-note.bin"] = json.dumps(linking, separators=(",", ":")).encode("utf-8")
        cls.inputs = inputs
        cls.values = run(inputs, extra_args=["--detection-log", "values"], expect=2, prefix="detection-values-")
        cls.addClassCleanup(cls.values.cleanup)
        cls.on = run(inputs, extra_args=["--detection-log", "on"], expect=2, prefix="detection-on-")
        cls.addClassCleanup(cls.on.cleanup)
        cls.files = {item["MessageId"]: item for item in cls.values.report["Items"]}

    @staticmethod
    def structure(result):
        """Each block's feed, outcome, counts and entry groups and tails, without transaction, location or values."""
        return sorted((b["header"].group(1), b["header"].group(3), b["header"].group(4), b["header"].group(5), b["header"].group(6),
                       b["header"].group(7), tuple((g, TAIL.search(line).group(0)) for g, line in b["entries"])) for b in blocks(result.console))

    def test_values_blocks_have_the_value_free_structure_plus_values(self):
        values, on = blocks(self.values.console), blocks(self.on.console)
        self.assertGreater(sum(len(b["entries"]) for b in values), 400)
        self.assertEqual(self.structure(self.values), self.structure(self.on))
        for block in values:
            for group, line in block["entries"]:
                before, after = values_of(line)
                self.assertIsInstance(before, str)
                changed = group == "pii" or "decision=masked-by-default" in line
                self.assertEqual(after is not None, changed, "a changed string shows before -> after; an unchanged one, its value once")

    def test_value_free_mode_still_has_no_values(self):
        text = "\n".join("\n".join(b["lines"][1:]) for b in blocks(self.on.console))
        self.assertNotIn(" -> ", text)
        leaked = leaked_values(text)
        self.assertEqual(leaked, [], "values found in value-free blocks: " + str(len(leaked)))
        self.assertNotIn("NewContactNote", text, "an undeclared property name stays ? without the values flag")

    def test_an_encoded_value_stays_on_one_line_reads_back_and_shows_its_published_value(self):
        entries = [line for b in blocks(self.values.console) for _, line in b["entries"] if location(line) == "/0/NewContactNote"]
        self.assertEqual(len(entries), 1)
        before, after = values_of(entries[0])
        self.assertEqual(before, self.NOTE)
        published = json.loads(self.values.published("PNR-Linking", "values-note.bin"))
        self.assertEqual(after, published[0]["NewContactNote"])
        self.assertNotIn("LINE ONE\nSAY", self.values.console)

    def test_binary_offsets_lead_to_the_value_in_the_decoded_payload(self):
        checked = 0
        for block in blocks(self.values.console):
            feed, transaction = block["header"].group(1), block["header"].group(2)
            if feed not in BINARY:
                continue
            payload = payload_of(self.inputs[f"{feed}/{Path(self.files[transaction]['Source']).name}"])
            for _, line in block["entries"]:
                offset = int(re.search(r"@0x([0-9A-F]+)", line).group(1), 16)
                before, _ = values_of(line)
                self.assertEqual(payload[offset:offset + len(before)].decode("ascii"), before, f"{feed} offset {offset:#x}")
                checked += 1
        self.assertGreater(checked, 200)

    def test_messages_rejected_before_detection_write_no_block(self):
        transactions = {b["header"].group(2) for b in blocks(self.values.console)}
        for feed, name in [("PNR-Linking", "PNR_LINKING_03_Negative_Testing.txt"), ("Seats", "SEATS_02_Negative_Testing.txt")]:
            item = self.values.status(feed, name, "Rejected")
            self.assertNotIn(item["MessageId"], transactions, f"{feed}/{name} was rejected before detection but has a block")

    def test_every_block_in_the_harness_console_parses_whole(self):
        # Every block line is indented, so any other line inside a block would end it early and its header counts would
        # no longer match. Detection itself is serialized by the engine gate, so this run alone cannot show that
        # concurrent writes are kept apart; FeedPipelineChecks writes blocks from many threads at once for that (R-011).
        for block in blocks(self.values.console):
            self.assertEqual(int(block["header"].group(4)), len(block["entries"]))

    def test_largest_block_stays_far_below_the_log_event_limit(self):
        largest = max(len("\n".join(b["lines"]).encode("utf-8")) for b in blocks(self.values.console))
        print(f"\nLARGEST-BLOCK {largest} bytes")
        self.assertLess(largest, 200_000)

    def test_the_run_summary_lists_review_fields_by_real_path_without_values(self):
        summary = (self.values.output_root / "detection-summary.txt").read_text(encoding="utf-8")
        for feed in ("ACI", "ETKT", "PNR", "PNR-Linking", "Seats"):
            self.assertRegex(summary, rf"(?m)^{re.escape(feed)}  review fields \(\d+ files\)$")
        self.assertRegex(summary, r"(?m)^  /\*/NewContactNote +masked-by-default +seen=1 .*files=values-note\.bin$")
        self.assertNotIn(self.NOTE, summary)
        self.assertNotIn(json.dumps(self.NOTE), summary)
        # Review R-008: a property name outside printable ASCII is JSON-encoded on its own line.
        self.assertRegex(summary, r'(?m)^  "/\*/Odd\\nKey" +masked-by-default ')
        self.assertFalse(any(line.startswith("Key") for line in summary.splitlines()), "a property name broke a summary line")
        # Feed headings name the feeds (a sample value such as "Seat" is part of "Seats"); only the entries are scanned.
        entries = "\n".join(line for line in summary.splitlines() if line.startswith("  ")).replace("/*/NewContactNote", "")
        self.assertEqual(leaked_values(entries), [], "values found in the summary")


class DetectionLogValuesRejectionTests(unittest.TestCase):
    """WR-020: a message dead-lettered after detection ran still gets its block, with values but no after values."""

    @classmethod
    def setUpClass(cls):
        import shutil
        import tempfile
        source = PROJECT / "src" / "PresidioDemo.Core" / "Configuration" / "recognizers"
        cls.folder = tempfile.TemporaryDirectory(prefix="widened-recognizers-", dir=PROJECT / ".test-runs")
        cls.addClassCleanup(cls.folder.cleanup)
        for path in source.glob("*.xml"):
            shutil.copy(path, cls.folder.name)
        # A declared format matching the whole ACI record reference would mask its embedded PNR: rejected after detection.
        aci = Path(cls.folder.name) / "aci.xml"
        text = aci.read_text(encoding="utf-8")
        keep = '<keep name="unresolvedRecordReference"'
        assert text.count(keep) == 1
        aci.write_text(text.replace(keep, '<format name="wholeReference" entity="UNCLASSIFIED_IDENTIFIER" score="0.95" maskCharacter="*">'
                                          r'<pattern>\d{9}\w{6}</pattern></format>' + '\n  ' + keep), encoding="utf-8")
        sample = (PROJECT / "docs" / "sample-docs" / "ACI" / "ACI.txt").read_bytes()
        cls.result = run({"ACI/ACI.txt": sample}, extra_args=["--detection-log", "values", "--recognizer-directory", cls.folder.name],
                         expect=2, prefix="detection-rejected-")
        cls.addClassCleanup(cls.result.cleanup)

    def test_dead_lettered_after_detection_writes_a_block_with_its_reason(self):
        item = self.result.status("ACI", "ACI.txt", "Rejected")
        self.assertIn("Protection changed an embedded PNR", self.result.reason("ACI", "ACI.txt"))
        found = [b for b in blocks(self.result.console) if b["header"].group(2) == item["MessageId"]]
        self.assertEqual(len(found), 1)
        header = found[0]["header"]
        self.assertEqual(header.group(3), "DEAD-LETTERED")
        self.assertIn("Protection changed an embedded PNR", json.loads(header.group(10)))
        changed = [line for group, line in found[0]["entries"] if group == "pii"]
        self.assertGreater(len(changed), 0)
        self.assertTrue(all(line.split("  format=")[0].endswith(" -> not published") for line in changed))
        self.assertTrue(all(values_of(line)[0] for _, line in found[0]["entries"]))


if __name__ == "__main__":
    unittest.main()
