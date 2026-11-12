"""Value-free verification of decoded-text protection against the frozen parity baseline (WR-019).

Shared by test_decoded_text_feeds.py and tests/run_sample_verification.py. Nothing here prints or returns a sample
value; failures name the sample, location and check only.
"""
from pathlib import Path
import json

PROJECT = Path(__file__).resolve().parents[2]
FIXTURES = PROJECT / "tests" / "fixtures"
BINARY = ("ACI", "ETKT", "PNR")
EXPECTED_REJECTIONS = {
    "PNR_LINKING_03_Negative_Testing.txt": "number or boolean that cannot be protected in its JSON type",
    "SEATS_02_Negative_Testing.txt": "UTF-8 CCSID 1208",
}
MASK_CHARACTERS = set(b"*#")


def payload(message):
    """Return the payload bytes of an IBM MQ export (X rows) or a raw payload."""
    lines = message.decode("utf-8", errors="strict").splitlines() if message[:2] == b"A " else None
    if lines is None:
        return message
    return bytes.fromhex("".join(line[2:].strip() for line in lines if line.startswith("X ")))


def header(message):
    """Return the MQ metadata rows of an export."""
    return [line for line in message.decode("utf-8").splitlines() if line.startswith("A ")]


def baseline():
    """Return the frozen baseline and the approved exceptions as (sample, location) keys."""
    document = json.loads((FIXTURES / "parity-baseline.json").read_text(encoding="utf-8"))
    exceptions = {(e["sample"], e["location"]) for e in json.loads((FIXTURES / "parity-exceptions.json").read_text(encoding="utf-8"))}
    return document, exceptions


def false_positives():
    """Return the listed false positives (WR-019) as (sample, location, length) keys."""
    entries = json.loads((FIXTURES / "false-positives.json").read_text(encoding="utf-8"))
    return {(e["sample"], e["location"], e["length"]) for e in entries}


def json_strings(node, path=""):
    """Yield (path, value) for every JSON string scalar, with paths in the baseline's /0/Customers/1/FirstName form."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from json_strings(value, path + "/" + key.replace("~", "~0").replace("/", "~1"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from json_strings(value, f"{path}/{index}")
    elif isinstance(node, str):
        yield path, node


def changed_runs(before, after):
    """Return (start, end) runs of changed bytes; unchanged literal * separators inside a masked string join runs."""
    runs, start, last = [], None, None
    for index, (left, right) in enumerate(zip(before, after)):
        if left == right:
            continue
        if start is not None and all(before[k] == 0x2A for k in range(last + 1, index)):
            last = index
            continue
        if start is not None:
            runs.append((start, last + 1))
        start = last = index
    if start is not None:
        runs.append((start, last + 1))
    return runs


def containing_string(data, start, end):
    """Return (offset, length) of the XDR counted string of printable ASCII holding bytes start..end, or the run itself.

    A counted string is a 4-byte big-endian length followed by its text at a 4-aligned offset, as the generic codec
    scans it; false positives are judged per string, like the spike, not per changed byte run.
    """
    for offset in range(start - start % 4, max(3, start - 1024), -4):
        length = int.from_bytes(data[offset - 4:offset], "big")
        if length >= 4 and offset + length >= end and all(32 <= b < 127 for b in data[offset:offset + length]):
            return offset, length
    return start, end - start


def json_value(document, location):
    """Return the scalar at a JSON instance path such as /0/Customers/1/FirstName."""
    node = document
    for segment in [s for s in location.split("/") if s]:
        key = segment.replace("~1", "/").replace("~0", "~")
        node = node[int(key)] if isinstance(node, list) else node[key]
    return node


def verify_published(feed, name, original, output, document=None, exceptions=None, listed=None):
    """Check one published sample; return value-free counts, raise AssertionError on a failed check."""
    if document is None:
        document, exceptions = baseline()
    if listed is None:
        listed = false_positives()
    before, after = payload(original), payload(output)
    checks = {"protected": 0, "approved_exceptions": 0, "pnrs_unchanged": 0, "listed_false_positives": 0}
    if original[:2] == b"A ":
        if header(original) != header(output):
            raise AssertionError(f"{name}: MQ metadata changed")
        if original.endswith(b"\n") != output.endswith(b"\n"):
            raise AssertionError(f"{name}: final newline changed")
        rows = [len(line) for line in original.splitlines() if line.startswith(b"X ")]
        # JSON replacements change the payload length, so only binary exports keep identical hex rows (WR-004).
        if feed in BINARY and rows != [len(line) for line in output.splitlines() if line.startswith(b"X ")]:
            raise AssertionError(f"{name}: MQ row framing changed")
    if feed in BINARY:
        if len(before) != len(after):
            raise AssertionError(f"{name}: binary payload length changed")
        for index, (left, right) in enumerate(zip(before, after)):
            if left != right and right not in MASK_CHARACTERS:
                raise AssertionError(f"{name}: byte {index} changed to a character that is not a mask character")
    else:
        left_json, right_json = json.loads(before), json.loads(after)
    for entry in document["protected"]:
        if entry["sample"] != name:
            continue
        if feed in BINARY:
            start, length = int(entry["location"]), entry["length"]
            caught = all(b == 0x2A or b != a for b, a in zip(before[start:start + length], after[start:start + length]))
        else:
            caught = json_value(left_json, entry["location"]) != json_value(right_json, entry["location"])
        if caught:
            checks["protected"] += 1
        elif (name, entry["location"]) in exceptions:
            checks["approved_exceptions"] += 1
        else:
            raise AssertionError(f"{name}: baseline {entry['entity']} at {entry['location']} was published unprotected")
    for entry in document["pnrs"]:
        if entry["sample"] != name:
            continue
        if feed in BINARY:
            start, length = int(entry["location"]), entry["length"]
            same = before[start:start + length] == after[start:start + length]
        else:
            same = json_value(left_json, entry["location"]) == json_value(right_json, entry["location"])
        if not same:
            raise AssertionError(f"{name}: PNR at {entry['location']} changed")
        checks["pnrs_unchanged"] += 1
    # WR-019: a changed string that the baseline protects nothing inside must be a listed false positive. Samples the
    # former design rejected have no baseline, so this applies to the baseline's samples only, as in the spike.
    if name not in document["samples"]:
        return checks
    protected = [e for e in document["protected"] if e["sample"] == name]
    if feed in BINARY:
        offsets = [int(e["location"]) for e in protected]
        counted = set()
        for start, end in changed_runs(before, after):
            offset, length = containing_string(before, start, end)
            if any(offset <= o < offset + length for o in offsets) or (offset, length) in counted:
                continue
            if (name, str(offset), length) not in listed:
                raise AssertionError(f"{name}: string at {offset} ({length} bytes) changed outside the baseline and the false-positive list")
            counted.add((offset, length))
            checks["listed_false_positives"] += 1
    else:
        locations = {e["location"] for e in protected}
        after_strings = dict(json_strings(right_json))
        for path, value in json_strings(left_json):
            if path in locations or after_strings.get(path) == value:
                continue
            if (name, path, len(value)) not in listed:
                raise AssertionError(f"{name}: string at {path} changed outside the baseline and the false-positive list")
            checks["listed_false_positives"] += 1
    return checks
