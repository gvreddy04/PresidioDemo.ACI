# ACI feed sample review and structure

> **Superseded design.** This review describes the per-feed parsers, field policies and the three XML files (`feed-policies.xml`, `xdr-layouts.xml`, `reference-layouts.xml`) that decoded-text detection replaced. Those files and parsers are removed. Protection now uses the generic decoder and the ACI recognizer file, which keeps passenger names only (`passengerName`); Presidio's predefined recognizers run too only with `Presidio:DefaultDetection` on, which is off by default. The other fields described below are published as received; see [Decoded-text detection](../README.md#decoded-text-detection). The sample review, the structure findings and the field meanings below stay valid as analysis; the configuration notes refer to the removed design. The protection results they produced are frozen, value-free, in [tests/fixtures/parity-baseline.json](../tests/fixtures/parity-baseline.json).
>
> This repository keeps the ACI feed only. The review of the other feeds, and the configuration examples of the removed design, are in the history of the earlier multi-feed repository at commit `dffbdad`.

All six files in `docs/sample-docs/ACI/` were reviewed without changing source bytes. Each is an MQ text export: `A` rows carry metadata and `X` rows carry hexadecimal payload bytes. All six are binary payloads, and none is a negative test.

## Binary representation

The examples use big-endian 32-bit words and counted ASCII strings padded to four bytes. A counted string consists of its byte length, that many text bytes and zero padding. An empty string is a length word of zero, with no value or padding. Missing text is therefore represented structurally, not by a special character. Actual `*` characters in populated fields are masked/placeholder content and are not universal missing-field markers.

The ACI declarations establish linked-list pointers guarded by XDR presence words, not array counts. The removed ACI schema reconstructed their nested structures, including four variable list presences, as a field-policy projection; a broader decoded shape did not automatically have processing approval or policy coverage.

The initial ACI word is two. The removed schema checked this observed discriminator. Subsequent words and string counts are parsed separately, and offsets are calculated while reading each message.

A scanner can read some pairs of raw words as a short counted string: for example `00000001 31000000` looks like a length-one string containing `1` with three zero pad bytes. The generic decoder therefore treats only strings of four or more printable characters as text and keeps shorter spans as raw words (WR-015).

## ACI

ACI has six examples, ACI.txt and ACI_02.txt (888 payload bytes each), ACI_03.txt and ACI_05.txt (832), ACI_04.txt (876) and ACI_06.txt (960). The C-structure definitions were checked against all six payloads. ACI is now decoded by `src/PresidioDemo.Core/Decoder/AciDecoder.cs` over `XdrFeedDecoder`, with no per-feed schema; the generic scanner finds 14 to 17 counted strings of four or more characters per sample. The analysis is kept for reference.

The removed decoder followed `seats_assigned` (ERROR=1 / DATA=2), flight/leg/compartment lists, passenger lists, passenger-flight items and nested seat, bag, registration, loyalty, profile, sequence, security, ticket, through-check-in, miscellaneous, history, consolidated-flight, codeshare, tier and transaction-time lists. Four-byte XDR scalar slots must not be confused with C memory sizes. Strings have length words and zero padding; null linked pointers have a zero presence word.

The samples contain one passenger-list node each, including those with party count two. `nbr_prty` is not a node count. The removed parser checked each passenger-flight `pax_id` against its owning passenger `paxl_id`; names, the record locator and node position are not used as unique passenger identity. Numeric IDs remain unchanged by the agreed scope. No tokenization was added.

The old `seatNumber` field is `leg_list.dept_gate`, later `departureGate`. The actual passenger seat is `seat_list.seat_nbr`. The old `origin` is `flight_list.trm_cty`, later `terminatingCity`; the leg city is `leg_list.cty_code`, later `legCity`. Confirmed equipment, aircraft number, gate, sector and process fields were kept. Passenger names, actual passenger seat assignments, loyalty numbers and unresolved identifiers were masked. Record-locator copies stayed unchanged and had to agree with the owning passenger.

All six samples contain an additional block after transaction times that is not defined in the available structure declarations. With explicit approval, it was represented as `unresolved_extension`: three observed scalar words, two counted strings and a next pointer. Its business meaning is unconfirmed. The first string was masked; the second kept its reviewed numeric-prefix mask and optional unchanged record-locator suffix. The `recordReferencePrefix` recognizer in `aci.xml` keeps that prefix mask.

The two-passenger shapes, some documented branches (such as the unusual placement of `fcpr_list.next` before spare members) and updated producer XDR routines are not covered by the supplied samples, so the samples do not establish a general producer contract. In the removed design, unsupported structures went to the dead-letter queue without publication until a reviewed schema represented them; decoded-text detection scans them instead (WR-016).

The immutable workspace review, decoded examples, searchable transcription and verification evidence are kept in the analyst's local workspace, outside this repository.

## Reviewed samples and results

Counts below describe populated binary text/capture fields under the removed field policies. Fixed structural tags, empty text slots and raw framing words are excluded. Retained verification evidence records source hashes and calculated field spans without personal values.

| Sample | Payload bytes | Kept | Masked |
| --- | ---: | ---: | ---: |
| ACI.txt | 888 | 20 | 3 Mask |
| ACI_02.txt | 888 | 20 | 3 Mask |
| ACI_03.txt | 832 | 19 | 1 Mask |
| ACI_04.txt | 876 | 19 | 2 Mask |
| ACI_05.txt | 832 | 18 | 1 Mask |
| ACI_06.txt | 960 | 19 | 5 Mask |

With decoded-text detection, all six samples are published through the real worker and local Presidio, with `Presidio:DefaultDetection` off. The parity check covers the ACI field list (QF-26112303): all 15 values the former field policies protected are in scope; 13 are protected (names, loyalty numbers, unresolved identifiers and record-reference prefixes), and the 2 short seat strings in `ACI_06.txt` are approved exceptions. The record locators, standalone or inside the unresolved record reference, stay unchanged. Source hashes, payload sizes, raw words, string counts, zero padding, MQ headers, row framing and newline style are preserved.

## Configuration behavior (removed design)

The removed design kept three XML files with these responsibilities:

| File | Responsibility |
| --- | --- |
| `reference-layouts.xml` | Readable field names, baseline offsets/lengths and optional capture mappings |
| `xdr-layouts.xml` | Ordered binary words, counted strings, padding, arrays and optional groups |
| `feed-policies.xml` | Per-feed Keep/Mask actions, with an optional shared catalog |

The worker validated them together before it connected to the broker; a restart applied changes. Every exposed scalar needed exactly one policy, unknown structure went to the dead-letter queue without publication, and new structural variations required reviewed XML. Decoded-text detection replaced all three files with `aci.xml`.

## Reviewed field names

ACI aliases use the documented meanings described above.

| Original field | Policy alias | Evidence and limits |
| --- | --- | --- |
| `recordTimestamp` | `flightAciTimestamp` | Structure `flight_list.flt_list_str3`, ACI timestamp in GMT |
| `recordTime` | `aciTransactionTime` | Structure `trans_times_list.trans_time3` |
| `secondaryAirlineCode` | `passengerFlightAirline` | Structure `paxflt_items.airline_code` |

ACI `Text0020` became `flightDate`, established by `flight_list.flt_date` in the structure declarations. `Text0132` was a false string inference, removed rather than renamed.

## Reproduce verification

```powershell
dotnet build PresidioDemo.slnx
dotnet run --project tests/FeedPipelineChecks
dotnet run --project tests/WorkerChecks
src/.venv/Scripts/python.exe -m unittest discover -s tests/unit-tests -p test_*.py -v
src/.venv/Scripts/python.exe tests/run_sample_verification.py
```

The sample verification runs all six ACI samples through `tests/FeedPipelineHarness`. It keeps the outputs, transaction logs and a value-free `verification.json` in a fresh `.test-runs/e2e-*` folder. The harness exits with code 0 because all six samples are published.
