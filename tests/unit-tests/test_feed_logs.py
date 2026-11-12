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
                  r"decision=(masked|kept|masked-inside|anchor|masked-by-default|missed-below-threshold)$")
GROUPS = {"  PII fields (changed)": "pii", "  Non-PII fields (unchanged)": "non-pii", "  Review (a format or keep may be needed)": "review"}
DECISIONS = {"pii": {"masked", "masked-inside"}, "non-pii": {"kept", "anchor"},
             "review": {"masked-by-default", "missed-below-threshold"}}


def payload_of(content):
    """The decoded payload of an MQ export (.txt) or a raw payload (.bin)."""
    text = content.decode("utf-8", errors="replace")
    rows = [line[2:].strip() for line in text.splitlines() if line.startswith("X ")]
    return bytes.fromhex("".join(rows)) if rows else content


def sample_values():
    """Every decoded value of the supplied samples: their XDR counted strings."""
    values = set()
    for path in sorted((PROJECT / "docs" / "sample-docs").rglob("*.txt")):
        payload = payload_of(path.read_bytes())
        offset = 0
        while offset + 4 <= len(payload):
            length = struct.unpack(">I", payload[offset:offset + 4])[0]
            end = offset + 4 + length
            if 0 < length <= len(payload) - offset - 4 and all(0x20 <= b <= 0x7E for b in payload[offset + 4:end]):
                values.add(payload[offset + 4:end].decode("ascii"))
                offset = end + (-length % 4)
            else:
                offset += 4
    return values


def shape(value):
    """The detection-log shape of a value: A for a letter, 9 for a digit, other characters unchanged."""
    return re.sub(r"[0-9]", "9", re.sub(r"[A-Za-z]", "A", value))


def leaked_values(text):
    """Sample values of 4+ characters found in text, except values identical to their own shape (such as 9999)."""
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


def values_of(line):
    """The JSON-encoded before and after values of a values-mode entry; after is None when unchanged or not published."""
    body = line[4:]
    body = body[re.match(r"slot \d+ @0x[0-9A-F]+", body).end():].lstrip()
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
            self.assertIsNotNone(header.group(8), "every block names its offset base")
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
        cls.original = (PROJECT / "docs/sample-docs/PNR/PNR_02.txt").read_bytes()
        cls.harness = run({"PNR/comparison.txt": cls.original}, expect=0, prefix="feed-logs-")
        cls.addClassCleanup(cls.harness.cleanup)

    def test_one_log_per_transaction_with_complete_before_and_after_sections(self):
        original = self.original
        item = self.harness.item("PNR", "comparison.txt")
        logs = list((self.harness.output_root / "logs").rglob("*"))
        self.assertEqual([p.name for p in logs if p.is_file()], ["comparison.txt.log.txt"])
        text = self.harness.log("PNR", "comparison.txt")
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
        output = self.harness.published("PNR", "comparison.txt")
        self.assertLess(after.index("Decoded MQ payload"), after.index("Complete feed data"))
        self.assertIn("Complete feed data (" + str(len(output)) + " bytes):", after)
        self.assertIn(output.decode("utf-8"), after)

    def test_the_file_block_carries_values(self):
        found = blocks(self.harness.log("PNR", "comparison.txt"))
        self.assertEqual(len(found), 1)
        self.assertTrue(all(values_of(line)[0] is not None for _, line in found[0]["entries"]))


class DetectionLogValuesTests(unittest.TestCase):
    """WR-020: --detection-log values (as Presidio:DetectionLogValues) adds before and after values to every entry;
    nothing else changes.

    Assertion messages name samples and counts only, never a value."""

    @classmethod
    def setUpClass(cls):
        samples = PROJECT / "docs" / "sample-docs"
        inputs = {f"{p.parent.name}/{p.name}": p.read_bytes() for p in sorted(samples.rglob("*.txt"))}
        # A truncated payload is rejected before detection, so it must write no block.
        inputs["PNR/truncated.bin"] = b"\0\0\0"
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
        self.assertGreater(sum(len(b["entries"]) for b in values), 100)
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

    def test_binary_offsets_lead_to_the_value_in_the_decoded_payload(self):
        checked = 0
        for block in blocks(self.values.console):
            feed, transaction = block["header"].group(1), block["header"].group(2)
            payload = payload_of(self.inputs[f"{feed}/{Path(self.files[transaction]['Source']).name}"])
            for _, line in block["entries"]:
                offset = int(re.search(r"@0x([0-9A-F]+)", line).group(1), 16)
                before, _ = values_of(line)
                self.assertEqual(payload[offset:offset + len(before)].decode("ascii"), before, f"{feed} offset {offset:#x}")
                checked += 1
        self.assertGreater(checked, 100)

    def test_messages_rejected_before_detection_write_no_block(self):
        transactions = {b["header"].group(2) for b in blocks(self.values.console)}
        item = self.values.status("PNR", "truncated.bin", "Rejected")
        self.assertNotIn(item["MessageId"], transactions, "PNR/truncated.bin was rejected before detection but has a block")

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

    def test_the_run_summary_lists_review_fields_by_slot_and_offset_without_values(self):
        summary = (self.values.output_root / "detection-summary.txt").read_text(encoding="utf-8")
        self.assertRegex(summary, r"(?m)^PNR  review fields \(\d+ files\)$")
        entries = [line for line in summary.splitlines() if line.startswith("  ")]
        self.assertGreater(len(entries), 0)
        self.assertTrue(all(re.match(r"  slot \d+ @0x[0-9A-F]+ +\S+ +seen=\d+ ", line) for line in entries),
                        "every summary entry is located by slot and payload offset")
        # Only the entries are scanned; the feed heading is a label.
        self.assertEqual(leaked_values("\n".join(entries)), [], "values found in the summary")


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
        # Test-only recognizers: a PNR embedded in the COCOM record (an optional embedded anchor) and a declared format
        # matching that whole record, which wins over its keep and would mask the embedded PNR: rejected after detection.
        pnr = Path(cls.folder.name) / "pnr.xml"
        text = pnr.read_text(encoding="utf-8")
        anchor, keep = '<pnrAnchor after="creationTime" offset="1" />', '<keep name="cocomRecord"'
        assert text.count(anchor) == 1 and text.count(keep) == 1
        text = text.replace(anchor, anchor + '\n  <pnrAnchor within="cocomRecord" optional="true">'
                                    r'<pattern>COCOM-[A-Z]{2}/(?&lt;pnr>[A-Z]{2}\d{4})\d{2,8}-GUID/</pattern></pnrAnchor>')
        text = text.replace(keep, '<format name="wholeCocom" entity="UNCLASSIFIED_IDENTIFIER" score="0.95" maskCharacter="*">'
                                  r'<pattern>COCOM-[A-Z]{2}/[A-Z]{2}\d{6,12}-GUID/</pattern></format>' + '\n  ' + keep)
        pnr.write_text(text, encoding="utf-8")
        sample = (PROJECT / "docs" / "sample-docs" / "PNR" / "PNR.txt").read_bytes()
        cls.result = run({"PNR/PNR.txt": sample}, extra_args=["--detection-log", "values", "--recognizer-directory", cls.folder.name],
                         expect=2, prefix="detection-rejected-")
        cls.addClassCleanup(cls.result.cleanup)

    def test_dead_lettered_after_detection_writes_a_block_with_its_reason(self):
        item = self.result.status("PNR", "PNR.txt", "Rejected")
        self.assertIn("Protection changed an embedded PNR", self.result.reason("PNR", "PNR.txt"))
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
