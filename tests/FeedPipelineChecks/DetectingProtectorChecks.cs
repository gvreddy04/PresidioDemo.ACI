using System.Buffers.Binary;
using System.Text;
using PresidioDemo.Core.Decoder;
using PresidioDemo.Core.Models;
using PresidioDemo.Core.Pipeline;
using PresidioDemo.Core.Protection;

/// <summary>
/// Checks the decoded-text protector (T-007): PNR anchors fail closed (V-06), detection failures dead-letter,
/// unmatched strings are masked, and every production sample rebuilds and validates.
/// </summary>
internal static class DetectingProtectorChecks
{

    #region Methods

    /// <summary>
    /// Runs the checks. Python must be started; the protector is configured here, after the failure-injection check.
    /// </summary>
    /// <param name="projectRoot">The repository root.</param>
    /// <returns>A task that completes when every check passed.</returns>
    public static async Task RunAsync(string projectRoot)
    {
        string recognizers = Path.Combine(projectRoot, "src", "PresidioDemo.Core", "Configuration", "recognizers");
        var sets = RecognizerConfiguration.Load(recognizers);
        string samples = Path.Combine(projectRoot, "docs", "sample-docs");
        var protector = new DetectingFeedProtector(sets);

        // Detection failure: the bridge has no registry for an unconfigured feed name, so the call fails and dead-letters.
        var unconfigured = new DetectingFeedProtector(new Dictionary<FeedType, FeedRecognizerSet> { [FeedType.ACI] = sets[FeedType.ACI] with { Feed = FeedType.ACI } });
        await RejectAsync(() => unconfigured.ProtectAsync(FeedType.ACI, Parse(Path.Combine(samples, "ACI", "ACI.txt")), CancellationToken.None),
            "Local Presidio detection failed", "a Presidio failure before configuration dead-letters");
        protector.Configure();

        int published = 0;
        foreach (string path in Directory.EnumerateFiles(samples, "*.txt", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            if (Path.GetFileName(path).Contains("Negative_Testing", StringComparison.Ordinal))
            {
                continue;
            }
            var feed = FeedFileRouting.FromPath(path);
            var codec = Codec(feed);
            var message = Message(path, feed);
            var parsed = codec.Parse(message);
            var outcome = await protector.ProtectAsync(feed, parsed, CancellationToken.None);
            byte[] output = codec.Serialize(parsed, outcome.Values);
            codec.Validate(parsed, output);
            var anchors = outcome.Events.Where(e => e.Decision == DetectionDecision.Anchor).ToArray();
            Check(anchors.Length > 0 || feed == FeedType.ETKT, Path.GetFileName(path) + ": a PNR anchor was found");
            var decoded = (feed is FeedType.ACI or FeedType.ETKT or FeedType.PNR ? parsed.Fields : JsonFeedParser.StringFields(parsed))
                .Select(f => f.Value).Where(v => v.Any(char.IsAsciiLetterOrDigit) && DetectingFeedProtector.Shape(v) != v).ToHashSet(StringComparer.Ordinal);
            Check(outcome.Events.All(e => !decoded.Contains(e.Shape) && !decoded.Contains(e.Key) && !decoded.Contains(e.Format) && !decoded.Contains(e.Entity)),
                Path.GetFileName(path) + ": no detection event field carries a decoded value");
            // WR-020: the decoded values travel beside the events, one per slot, for the values flag only.
            var candidateValues = (feed is FeedType.ACI or FeedType.ETKT or FeedType.PNR ? parsed.Fields : JsonFeedParser.StringFields(parsed)).Select(f => f.Value);
            Check(outcome.CandidateValues is { } carried && carried.Count == outcome.Events.Count && carried.SequenceEqual(candidateValues),
                Path.GetFileName(path) + ": the candidate values match the decoded strings by slot");
            // WR-018: a binary string is located by its payload offset only; a JSON value-free pointer holds no value.
            if (feed is FeedType.ACI or FeedType.ETKT or FeedType.PNR)
            {
                var payload = FeedPayloadReader.Read(message).Payload;
                Check(outcome.Events.Zip(parsed.Fields).All(pair => pair.First.Offset is int at && pair.First.Pointer.Length == 0 && pair.First.SafePointer.Length == 0 &&
                    Encoding.ASCII.GetString(payload.AsSpan(at, pair.Second.Value.Length)) == pair.Second.Value), Path.GetFileName(path) + ": each binary event's offset leads to its value");
            }
            else
            {
                // Array indexes are digits and may equal a short numeric string value; only property names are checked.
                Check(outcome.Events.All(e => e.Offset is null && e.SafePointer.Split('/').All(segment => segment.All(char.IsAsciiDigit) || !decoded.Contains(segment))),
                    Path.GetFileName(path) + ": no value-free JSON pointer carries a decoded value");
            }
            published++;
        }
        Console.WriteLine($"PASS {published} production samples protected, rebuilt and validated with the recognizer sets");

        // WR-018, WR-020: one block per message; every string in exactly one group; values only when passed, JSON-encoded.
        DetectionEvent[] events =
        [
            new(0, "", 13, "AAAAAA/AAAAAA", "passengerName", "PERSON", 0.9, DetectionDecision.Masked, Offset: 0x01A4),
            new(1, "", 6, "AAA999", "anchor", "PNR", 1, DetectionDecision.Anchor, Offset: 0x0018),
            new(2, "", 22, "AAAA AAA", "none", "", 0, DetectionDecision.MaskedByDefault, Offset: 0x0200),
            new(3, "", 6, "AA9999", "flightNumber", "", 0, DetectionDecision.Kept, Offset: 0x00E0),
            new(4, "", 10, "AA99999999", "loyalty", "LOYALTY", 0.3, DetectionDecision.MissedBelowThreshold, Offset: 0x0288),
            new(5, "", 7, "[AAAAA]", "dob", "DATE_OF_BIRTH", 1, DetectionDecision.Replaced, Offset: 0x02A0),
            new(6, "", 12, "AAAA AAAAAAA", "remark", "PERSON", 0.85, DetectionDecision.MaskedInside, Offset: 0x02C0),
        ];
        string[] fictionalBefore = ["MILLER/JORDAN", "ABC123", "LINE ONE\nSAY \"HI\" \\ X", "XY1234", "XY99887766", "14MAR85", "CALL O'NEIL"];
        string[] fictionalAfter = ["######/######", "ABC123", "######################", "XY1234", "XY99887766", "[DOB]", "CALL ######"];
        string[] Lines(string block) => block.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        string Section(string block, string heading)
        {
            var lines = Lines(block);
            int start = Array.FindIndex(lines, line => line == "  " + heading);
            int end = Array.FindIndex(lines, start + 1, line => !line.StartsWith("    ", StringComparison.Ordinal));
            return string.Join("\n", lines[(start + 1)..(end < 0 ? lines.Length : end)]);
        }
        var log = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, events);
        var valued = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, events, before: fictionalBefore, after: fictionalAfter);
        Check(Lines(log)[0] == "PNR " + Guid.Empty.ToString("N") + " DETECTION PUBLISHED strings=7 pii=3 non-pii=2 review=2 offsets=payload",
            "the header names the feed, transaction, outcome, counts and offset base");
        Check(Lines(log).Skip(1).All(line => line.StartsWith(' ')) && Lines(valued).Skip(1).All(line => line.StartsWith(' ')),
            "every line after the header is indented, so a collector keeps the block as one entry");
        string pii = Section(log, "PII fields (changed)"), nonPii = Section(log, "Non-PII fields (unchanged)"), review = Section(log, "Review (a format or keep may be needed)");
        Check(new[] { "@0x01A4", "@0x02A0", "@0x02C0" }.All(pii.Contains) && new[] { "@0x0018", "@0x00E0" }.All(nonPii.Contains)
            && new[] { "@0x0200", "@0x0288" }.All(review.Contains), "each decision is listed in its group, located by slot and offset");
        Check(Lines(log).Count(line => line.Contains(" @0x", StringComparison.Ordinal)) == events.Length, "each string appears exactly once");
        Check(review.Contains("masked-by-default", StringComparison.Ordinal) && review.Split('\n').Single(line => line.Contains("@0x0200", StringComparison.Ordinal)).Contains("  changed  ", StringComparison.Ordinal)
            && review.Split('\n').Single(line => line.Contains("@0x0288", StringComparison.Ordinal)).Contains("  unchanged  ", StringComparison.Ordinal),
            "a review entry says whether the string changed");
        Check(fictionalBefore.All(value => !log.Contains(value, StringComparison.Ordinal)) && fictionalAfter.Where(value => !value.All(c => c == '#')).All(value => !log.Contains(value, StringComparison.Ordinal))
            && !log.Contains("->", StringComparison.Ordinal) && log.Contains("len=13 shape=AAAAAA/AAAAAA", StringComparison.Ordinal),
            "a value-free block carries lengths and shapes, never a value");
        Check(Lines(valued).Length == Lines(log).Length, "an encoded value never breaks a line");
        Check(valued.Contains("\"MILLER/JORDAN\" -> \"######/######\"", StringComparison.Ordinal) && valued.Contains("\"CALL O'NEIL\" -> \"CALL ######\"", StringComparison.Ordinal)
            && Section(valued, "Non-PII fields (unchanged)").Contains("\"ABC123\"  format=anchor", StringComparison.Ordinal),
            "a changed string shows before -> after; an unchanged string shows its value once");
        string encoded = Lines(valued).Single(line => line.Contains("@0x0200", StringComparison.Ordinal));
        string quoted = encoded[(encoded.IndexOf('"', StringComparison.Ordinal))..encoded.IndexOf(" -> ", StringComparison.Ordinal)];
        Check(System.Text.Json.JsonSerializer.Deserialize<string>(quoted) == fictionalBefore[2], "an encoded value reads back exactly");
        var rejected = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, events, "Protection changed a PNR.", fictionalBefore, null);
        Check(Lines(rejected)[0].EndsWith(" DETECTION DEAD-LETTERED strings=7 pii=3 non-pii=2 review=2 offsets=payload reason=\"Protection changed a PNR.\"", StringComparison.Ordinal)
            && rejected.Contains("\"MILLER/JORDAN\" -> not published", StringComparison.Ordinal), "a dead-lettered block gives the reason and no after value");
        var keptOnly = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, [events[3]]);
        Check(Section(keptOnly, "PII fields (changed)") == "    (none)" && Section(keptOnly, "Review (a format or keep may be needed)") == "    (none)",
            "an empty group is printed as (none)");
        // Review R-003: fewer values than events must not fail; a slot without a value keeps the value-free form.
        var shortValues = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, events, before: ["MILLER/JORDAN"], after: fictionalAfter);
        Check(shortValues.Contains("\"MILLER/JORDAN\" -> \"######/######\"", StringComparison.Ordinal) && shortValues.Contains("len=6 shape=AAA999", StringComparison.Ordinal),
            "a slot without a value keeps the value-free form");
        DetectionEvent[] jsonEvents = [new(0, "?", 4, "AAAA", "none", "", 0, DetectionDecision.MaskedByDefault, "/0/con\ntacts/j.miller@example.com", "/0/?/?", "/*/con\ntacts/j.miller@example.com")];
        var jsonFree = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PnrLinking, Guid.Empty, jsonEvents);
        var jsonValued = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PnrLinking, Guid.Empty, jsonEvents, before: ["HOME"], after: ["####"]);
        Check(jsonFree.Contains("    /0/?/?  len=4 shape=AAAA  changed", StringComparison.Ordinal) && !jsonFree.Contains("miller", StringComparison.Ordinal)
            && !Lines(jsonFree)[0].Contains("offsets=", StringComparison.Ordinal), "a value-free JSON entry shows undeclared names as ?");
        Check(jsonValued.Contains("    \"/0/con\\ntacts/j.miller@example.com\"  \"HOME\" -> \"####\"", StringComparison.Ordinal) && Lines(jsonValued).Length == Lines(jsonFree).Length,
            "a values JSON entry shows the full pointer, encoded so a key cannot break the line");
        Console.WriteLine("PASS the detection log writes one grouped block per message, with values only when passed (WR-018, WR-020)");

        // ACI: the PNR is found next to the passenger name whether it is string 9 or string 8 (W-019).
        foreach (string name in new[] { "ACI.txt", "ACI_05.txt" })
        {
            var outcome = await protector.ProtectAsync(FeedType.ACI, Parse(Path.Combine(samples, "ACI", name)), CancellationToken.None);
            var anchor = outcome.Events.Single(e => e.Decision == DetectionDecision.Anchor);
            var nameEvent = outcome.Events.First(e => e.Format == "passengerName");
            Check(anchor.Slot == nameEvent.Slot - 1 && anchor.Length == 6, name + ": PNR anchored just before the passenger name");
        }
        Console.WriteLine("PASS ACI PNR anchored before the first passenger name in ACI.txt and ACI_05.txt");

        // V-06: a removed neighbour or a PNR that is no longer PNR-shaped dead-letters the message.
        string aci = Path.Combine(samples, "ACI", "ACI.txt");
        await RejectAsync(() => protector.ProtectAsync(FeedType.ACI, ParseEdited(aci, FeedType.ACI, (fields, payload) =>
            Overwrite(payload, fields.First(f => f.Value.Contains('/') && f.Value.Count(c => c == '/') == 1 && !f.Value.Any(char.IsDigit)), '/', 'X')), CancellationToken.None),
            "PNR anchor is missing", "a missing passenger-name neighbour dead-letters ACI");
        await RejectAsync(() => protector.ProtectAsync(FeedType.ACI, ParseEdited(aci, FeedType.ACI, (fields, payload) =>
        {
            int nameSlot = fields.ToList().FindIndex(f => f.Value.Contains('/') && !f.Value.Any(char.IsDigit));
            OverwriteFirst(payload, fields[nameSlot - 1], '-');
        }), CancellationToken.None), "anchor position is not PNR-shaped", "a PNR that is not PNR-shaped dead-letters ACI");
        await RejectAsync(() => protector.ProtectAsync(FeedType.PNR, ParseEdited(Path.Combine(samples, "PNR", "PNR.txt"), FeedType.PNR, (fields, payload) =>
            OverwriteFirst(payload, fields.First(f => f.Value.Length == 9 && f.Value.All(char.IsAsciiDigit)), 'A')), CancellationToken.None),
            "PNR anchor is missing", "a missing creation-time neighbour dead-letters PNR");
        var linking = Parse(Path.Combine(samples, "PNR-Linking", "PNR_LINKING.txt"));
        var brokenLinking = new ParsedFeed(linking.Fields.Select(f => f.Name.EndsWith("/UaRecordLocator", StringComparison.Ordinal) ? f with { Value = "AB" } : f).ToArray(), linking.Layout);
        await RejectAsync(() => protector.ProtectAsync(FeedType.PnrLinking, StringLayout(linking, brokenLinking), CancellationToken.None),
            "not PNR-shaped", "a JSON PNR anchor that is not PNR-shaped dead-letters PNR-Linking");

        // A number under a personal-data key (PNR_LINKING_03's numeric DOB) cannot be protected in its type: dead-letter.
        await RejectAsync(() => protector.ProtectAsync(FeedType.PnrLinking, Parse(Path.Combine(samples, "PNR-Linking", "PNR_LINKING_03_Negative_Testing.txt")), CancellationToken.None),
            "number or boolean", "a numeric value under a personal-data key dead-letters PNR_LINKING_03");

        // Unmatched strings are masked across their full width, keeping literal * separators (WR-014).
        Check(DetectingFeedProtector.DefaultMask("Q7 ZZ*AB", '#') == "#####*##", "default mask keeps width and literal *");
        var etkt = await protector.ProtectAsync(FeedType.ETKT, Parse(Path.Combine(samples, "ETKT", "ETKT_05.txt")), CancellationToken.None);
        Check(etkt.Events.Count(e => e.Decision == DetectionDecision.Anchor) == 2, "ETKT_05 divide-event PNRs anchored after the status record");
        var etktPlain = await protector.ProtectAsync(FeedType.ETKT, Parse(Path.Combine(samples, "ETKT", "ETKT.txt")), CancellationToken.None);
        Check(etktPlain.Events.All(e => e.Decision != DetectionDecision.Anchor), "ETKT without divide-event PNRs has no anchor and is not rejected");
        Check(etktPlain.Events.Any(e => e.Decision == DetectionDecision.MaskedByDefault) || etktPlain.Events.Any(e => e.Decision == DetectionDecision.Masked),
            "ETKT protects its ticket and reference strings");
        Console.WriteLine("PASS PNR anchors fail closed and unmatched strings are masked by default");

        // R-002, WR-017: a malformed divide-event PNR at an optional ETKT anchor position dead-letters instead of being
        // masked and published; so does a malformed PNR embedded in the ACI unresolved record reference.
        string etkt05 = Path.Combine(samples, "ETKT", "ETKT_05.txt");
        await RejectAsync(() => protector.ProtectAsync(FeedType.ETKT, ParseEdited(etkt05, FeedType.ETKT, (fields, payload) =>
        {
            int status = fields.ToList().FindIndex(f => f.Value.Length == 8 && f.Value.All(char.IsAsciiDigit));
            OverwriteFirst(payload, fields[status + 1], '-');
        }), CancellationToken.None), "anchor position is not PNR-shaped", "a malformed ETKT divide-event PNR dead-letters");
        await RejectAsync(() => protector.ProtectAsync(FeedType.ACI, ParseEdited(aci, FeedType.ACI, (fields, payload) =>
        {
            var reference = fields.Last(f => f.Value.Length == 15 && f.Value[..9].All(char.IsAsciiDigit));
            payload[Locate(payload, reference.Value) + 9] = (byte)'-';
        }), CancellationToken.None), "embedded PNR", "a malformed PNR embedded in the ACI record reference dead-letters");
        var aciOutcome = await protector.ProtectAsync(FeedType.ACI, Parse(aci), CancellationToken.None);
        var aciFields = Parse(aci).Fields;
        var referenceField = aciFields.Last(f => f.Value.Length == 15 && f.Value[..9].All(char.IsAsciiDigit));
        Check(aciOutcome.Values[referenceField.Id][9..] == referenceField.Value[9..] && aciOutcome.Values[referenceField.Id][..9].All(c => c == '*'),
            "ACI record reference: prefix masked, embedded PNR unchanged");
        // R-011: an all-digit 15-digit number in the reference position is not a record reference; it is masked in full.
        var digits = ParseEdited(aci, FeedType.ACI, (fields, payload) =>
        {
            var reference = fields.Last(f => f.Value.Length == 15 && f.Value[..9].All(char.IsAsciiDigit));
            System.Text.Encoding.ASCII.GetBytes("378282246310005").CopyTo(payload, Locate(payload, reference.Value));
        });
        var digitsOutcome = await protector.ProtectAsync(FeedType.ACI, digits, CancellationToken.None);
        var digitsField = digits.Fields.Single(f => f.Value == "378282246310005");
        Check(digitsOutcome.Values[digitsField.Id].All(c => c is '*' or '#'), "a 15-digit number in the reference position is masked in full");
        Console.WriteLine("PASS malformed optional and embedded PNRs dead-letter; the embedded ACI PNR is kept while its prefix is masked; an all-digit reference is masked in full");

        // WR-017: a protection that would change a PNR dead-letters. A declared format that matches the whole record
        // reference wins over its keep and would mask the embedded PNR. (Whole-string anchors never reach protection.)
        string scratch = Path.Combine(Path.GetTempPath(), "pnr-change-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        try
        {
            string aciFile = Path.Combine(scratch, "aci.xml");
            string valid = File.ReadAllText(Path.Combine(projectRoot, "src", "PresidioDemo.Core", "Configuration", "recognizers", "aci.xml"));
            const string keepElement = "<keep name=\"unresolvedRecordReference\"";
            Check(valid.Contains(keepElement, StringComparison.Ordinal), "aci.xml declares the unresolved record reference keep");
            File.WriteAllText(aciFile, valid.Replace(keepElement,
                "<format name=\"wholeReference\" entity=\"UNCLASSIFIED_IDENTIFIER\" score=\"0.95\" maskCharacter=\"*\"><pattern>\\d{9}\\w{6}</pattern></format>\n  " + keepElement));
            var widened = new DetectingFeedProtector(new Dictionary<FeedType, FeedRecognizerSet>(sets) { [FeedType.ACI] = RecognizerConfiguration.LoadFile(aciFile, FeedType.ACI) });
            widened.Configure();
            await RejectAsync(() => widened.ProtectAsync(FeedType.ACI, Parse(aci), CancellationToken.None),
                "Protection changed an embedded PNR", "a protection that would change the embedded ACI PNR dead-letters");
            // WR-020: a rejection after detection keeps its events and values, with the reason unchanged.
            var afterDetection = await new FeedMessageProcessor(FeedPipelineConfiguration.Load(recognizers).CreateRouter(widened))
                .ProcessAsync(FeedType.ACI, Guid.NewGuid(), "ACI.txt", File.ReadAllBytes(aci), CancellationToken.None);
            Check(!afterDetection.Published && afterDetection.Reason == "Protection changed an embedded PNR."
                && afterDetection.DetectionEvents is { Count: > 0 } kept && afterDetection.DetectionValues?.Count == kept.Count,
                "a message dead-lettered after detection keeps its events and values, with the same reason");
            Console.WriteLine("PASS a message dead-lettered after detection keeps its events and values for the detection log (WR-020)");
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
            // The bridge keeps one registry per feed, so restore the reviewed ACI recognizers for the checks that follow.
            protector.Configure();
        }
        // WR-020: a message rejected before detection has no events to log.
        var reviewed = new FeedMessageProcessor(FeedPipelineConfiguration.Load(recognizers).CreateRouter(protector));
        foreach (var (feed, name, input) in new[]
        {
            (FeedType.Seats, "SEATS_02_Negative_Testing.txt", File.ReadAllBytes(Path.Combine(samples, "Seats", "SEATS_02_Negative_Testing.txt"))),
            (FeedType.ACI, "truncated.bin", new byte[] { 0, 0, 0 }),
        })
        {
            var before = await reviewed.ProcessAsync(feed, Guid.NewGuid(), name, input, CancellationToken.None);
            Check(!before.Published && before.DetectionEvents is null && before.DetectionValues is null, name + ": rejected before detection, so nothing to log");
        }
        Console.WriteLine("PASS messages rejected before detection carry no events or values");

        // R-004, R-006, R-009: JSON keys match regardless of case, reason text is scanned, a number nested under a
        // personal-data key dead-letters, and a key the recognizer file does not declare is logged as ?.
        var linkingCodec = FeedCodecRegistry.Create(FeedType.PnrLinking);
        var json = linkingCodec.Parse(new FeedMessage(new FeedDelivery(FeedType.PnrLinking, Guid.NewGuid(), "fixture.bin", ""), Encoding.UTF8.GetBytes(
            "[{\"PNROwner\":\"K7QX2M\",\"dob\":\"1985-03-12\",\"ReasonForLeaving\":\"REBOOKED, CONTACT MILLER/JORDAN\",\"contacts\":{\"jordan.miller@example.com\":\"HOME\"}}]")));
        var jsonOutcome = await protector.ProtectAsync(FeedType.PnrLinking, json, CancellationToken.None);
        string Value(string suffix) => jsonOutcome.Values[json.Fields.Single(f => f.Id.EndsWith(suffix, StringComparison.Ordinal)).Id];
        Check(Value("/dob") == "[DATE_OF_BIRTH]", "a lower-case dob key is replaced, not kept as a timestamp");
        var nested = linkingCodec.Parse(new FeedMessage(new FeedDelivery(FeedType.PnrLinking, Guid.NewGuid(), "fixture.bin", ""),
            Encoding.UTF8.GetBytes("[{\"PNROwner\":\"K7QX2M\",\"DOB\":{\"Date\":\"1985-03-12\"}}]")));
        var nestedOutcome = await protector.ProtectAsync(FeedType.PnrLinking, nested, CancellationToken.None);
        Check(nestedOutcome.Values[nested.Fields.Single(f => f.Id.EndsWith("/DOB/Date", StringComparison.Ordinal)).Id] == "[DATE_OF_BIRTH]",
            "a string nested under a personal-data key is protected by that key (R-012)");
        Check(!Value("/ReasonForLeaving").Contains("MILLER", StringComparison.Ordinal) && Value("/ReasonForLeaving").StartsWith("REBOOKED, ", StringComparison.Ordinal),
            "a name inside reason text is masked while the reason is kept");
        Check(Value("/PNROwner") == "K7QX2M", "the PNR stays unchanged");
        Check(jsonOutcome.Events.Single(e => e.Decision == DetectionDecision.MaskedByDefault).Key == "?", "an undeclared key is logged as ?");
        var dynamicKey = jsonOutcome.Events.Single(e => e.Decision == DetectionDecision.MaskedByDefault);
        Check(dynamicKey.SafePointer == "/0/?/?" && dynamicKey.Pointer == "/0/contacts/jordan.miller@example.com" && dynamicKey.Pattern == "/*/contacts/jordan.miller@example.com",
            "a value-free pointer shows undeclared names as ? and keeps the array index; the full pointer keeps every name");
        Check(jsonOutcome.Events.Single(e => e.Decision == DetectionDecision.Anchor).SafePointer == "/0/PNROwner", "a declared key keeps its name in the value-free pointer");
        await RejectAsync(() => protector.ProtectAsync(FeedType.PnrLinking, linkingCodec.Parse(new FeedMessage(new FeedDelivery(FeedType.PnrLinking, Guid.NewGuid(), "fixture.bin", ""),
            Encoding.UTF8.GetBytes("[{\"PNROwner\":\"K7QX2M\",\"DOB\":{\"Year\":1985}}]"))), CancellationToken.None),
            "number or boolean", "a number nested under a personal-data key dead-letters");
        Console.WriteLine("PASS JSON keys ignore case, reason text is scanned, nested personal-data numbers dead-letter, undeclared keys log as ?");

        // R-003: a recognizer pattern that times out in Presidio dead-letters instead of publishing unchecked text. This
        // reconfigures the Seats registry, so it restores the reviewed configuration afterwards.
        string slow = Path.Combine(Path.GetTempPath(), "slow-seats-" + Guid.NewGuid().ToString("N") + ".xml");
        File.WriteAllText(slow, File.ReadAllText(Path.Combine(projectRoot, "src", "PresidioDemo.Core", "Configuration", "recognizers", "seats.xml"))
            .Replace("<keep name=\"operational\">", "<format name=\"slowCheck\" entity=\"DEMO_CODE\"><pattern>(A|AA)+$</pattern></format>\n  <keep name=\"operational\">", StringComparison.Ordinal));
        try
        {
            var slowSets = sets.ToDictionary(pair => pair.Key, pair => pair.Value);
            slowSets[FeedType.Seats] = RecognizerConfiguration.LoadFile(slow, FeedType.Seats);
            var slowProtector = new DetectingFeedProtector(slowSets);
            slowProtector.Configure();
            var seatsCodec = FeedCodecRegistry.Create(FeedType.Seats);
            var seats = seatsCodec.Parse(new FeedMessage(new FeedDelivery(FeedType.Seats, Guid.NewGuid(), "fixture.bin", ""),
                Encoding.UTF8.GetBytes("{\"UARecloc\":\"K7QX2M\",\"Note\":\"" + new string('A', 40) + "!\"}")));
            await RejectAsync(() => slowProtector.ProtectAsync(FeedType.Seats, seats, CancellationToken.None),
                "Local Presidio detection failed", "a Presidio pattern timeout dead-letters the message");
        }
        finally
        {
            File.Delete(slow);
            protector.Configure();
        }

        // V-12, W-017: the ACI passenger-association check is gone. Raw words such as numeric passenger IDs are never
        // decoded or changed, so a message whose ID word differs is published with that word exactly as received.
        var aciCodec = new AciDecoder();
        var aciMessage = Message(aci, FeedType.ACI);
        var aciEnvelope = FeedPayloadReader.Read(aciMessage);
        var aciCandidates = XdrFeedDecoder.Candidates(aciCodec.Parse(aciMessage));
        int nameEnd = aciCandidates.First(c => c.Value.Contains('/')).Offset + aciCandidates.First(c => c.Value.Contains('/')).Length;
        int idWord = Enumerable.Range(0, aciEnvelope.Payload.Length / 4).Select(i => i * 4)
            .First(o => o > nameEnd && !aciCandidates.Any(c => o + 4 > c.Offset - 4 && o < c.Offset + c.Length + 4) &&
                BinaryPrimitives.ReadUInt32BigEndian(aciEnvelope.Payload.AsSpan(o, 4)) is > 1 and < 100_000_000);
        byte[] mismatched = aciEnvelope.Payload.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(mismatched.AsSpan(idWord, 4), BinaryPrimitives.ReadUInt32BigEndian(mismatched.AsSpan(idWord, 4)) + 1);
        var mismatchMessage = new FeedMessage(aciMessage.Delivery, aciEnvelope.Serialize(mismatched));
        var mismatchParsed = aciCodec.Parse(mismatchMessage);
        var mismatchOutcome = await protector.ProtectAsync(FeedType.ACI, mismatchParsed, CancellationToken.None);
        byte[] mismatchOutput = aciCodec.Serialize(mismatchParsed, mismatchOutcome.Values);
        aciCodec.Validate(mismatchParsed, mismatchOutput);
        Check(FeedPayloadReader.Read(new FeedMessage(aciMessage.Delivery, mismatchOutput)).Payload.AsSpan(idWord, 4).SequenceEqual(mismatched.AsSpan(idWord, 4)),
            "ACI ID word published unchanged");
        Console.WriteLine("PASS an ACI message with a changed passenger-ID word is published with the word unchanged (no association check)");

        // V-09, WR-019: narrowing a format breaks parity with the frozen baseline before merge. This reconfigures the
        // PNR registry, so it runs last and restores the reviewed configuration afterwards.
        string narrowed = Path.Combine(Path.GetTempPath(), "narrowed-pnr-" + Guid.NewGuid().ToString("N") + ".xml");
        File.WriteAllText(narrowed, File.ReadAllText(Path.Combine(recognizers, "pnr.xml"))
            .Replace("<pattern>(?&lt;![A-Z])[A-Z]{2,}(?:[ '-][A-Z]+)*/[A-Z]*(?:[ '-][A-Z]+)*</pattern>", "<pattern>(?&lt;![A-Z])[A-Z]{30,}/[A-Z]{30,}</pattern>", StringComparison.Ordinal));
        try
        {
            var narrowedSets = sets.ToDictionary(pair => pair.Key, pair => pair.Value);
            narrowedSets[FeedType.PNR] = RecognizerConfiguration.LoadFile(narrowed, FeedType.PNR);
            int reviewedMisses = await ParityMissesAsync(protector, projectRoot, FeedType.PNR);
            Check(reviewedMisses == 0, "reviewed recognizers must have no unapproved PNR parity miss");
            // The bridge keeps one registry per feed name, so configuring the narrowed set replaces the reviewed one.
            var narrowedProtector = new DetectingFeedProtector(narrowedSets);
            narrowedProtector.Configure();
            int narrowedMisses = await ParityMissesAsync(narrowedProtector, projectRoot, FeedType.PNR);
            Check(narrowedMisses > 0, "a narrowed name format must fail parity");
            Console.WriteLine($"PASS a narrowed PNR name format fails parity with the frozen baseline ({narrowedMisses} unapproved misses)");
        }
        finally
        {
            File.Delete(narrowed);
            protector.Configure();
        }
    }

    /// <summary>
    /// Counts baseline values of one binary feed that the protector publishes unchanged and that are not approved
    /// exceptions (WR-019). Value-free: compares bytes at the frozen locations only.
    /// </summary>
    /// <param name="protector">The protector to measure.</param>
    /// <param name="projectRoot">The repository root.</param>
    /// <param name="feed">A binary feed.</param>
    /// <returns>The number of unapproved misses.</returns>
    private static async Task<int> ParityMissesAsync(DetectingFeedProtector protector, string projectRoot, FeedType feed)
    {
        using var baseline = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(projectRoot, "tests", "fixtures", "parity-baseline.json")));
        using var approved = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(projectRoot, "tests", "fixtures", "parity-exceptions.json")));
        var exceptions = approved.RootElement.EnumerateArray().Select(e => (e.GetProperty("sample").GetString(), e.GetProperty("location").GetString())).ToHashSet();
        string folder = FeedCatalog.Get(feed).FolderName;
        int misses = 0;
        foreach (var group in baseline.RootElement.GetProperty("protected").EnumerateArray().Where(e => e.GetProperty("feed").GetString() == folder)
            .GroupBy(e => e.GetProperty("sample").GetString()!))
        {
            string path = Path.Combine(projectRoot, "docs", "sample-docs", folder, group.Key);
            var codec = FeedCodecRegistry.Create(feed);
            var message = Message(path, feed);
            var parsed = codec.Parse(message);
            var outcome = await protector.ProtectAsync(feed, parsed, CancellationToken.None);
            byte[] before = FeedPayloadReader.Read(message).Payload;
            byte[] after = FeedPayloadReader.Read(new FeedMessage(message.Delivery, codec.Serialize(parsed, outcome.Values))).Payload;
            foreach (var entry in group)
            {
                int offset = int.Parse(entry.GetProperty("location").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
                int length = entry.GetProperty("length").GetInt32();
                // Only characters that were not already * need to change; a value that is all * was masked before it arrived.
                bool caught = Enumerable.Range(offset, length).Where(i => before[i] != (byte)'*').All(i => before[i] != after[i]);
                if (!caught && !exceptions.Contains((group.Key, entry.GetProperty("location").GetString())))
                {
                    misses++;
                }
            }
        }
        return misses;
    }

    /// <summary>
    /// Returns the codec the decoded-text path uses for a feed.
    /// </summary>
    private static IFeedCodec Codec(FeedType feed) => feed is FeedType.ACI or FeedType.ETKT or FeedType.PNR ? FeedCodecRegistry.Create(feed) : FeedCodecRegistry.Create(feed);

    /// <summary>
    /// Builds a message from a sample file.
    /// </summary>
    private static FeedMessage Message(string path, FeedType feed) => new(new FeedDelivery(feed, Guid.NewGuid(), Path.GetFileName(path), path), File.ReadAllBytes(path));

    /// <summary>
    /// Parses a sample with the decoded-text codec of its feed.
    /// </summary>
    private static ParsedFeed Parse(string path)
    {
        var feed = FeedFileRouting.FromPath(path);
        return Codec(feed).Parse(Message(path, feed));
    }

    /// <summary>
    /// Parses a binary sample after editing its payload bytes in place (same width), as a changed producer would.
    /// </summary>
    private static ParsedFeed ParseEdited(string path, FeedType feed, Action<IReadOnlyList<FeedField>, byte[]> edit)
    {
        var message = Message(path, feed);
        var codec = FeedCodecRegistry.Create(feed);
        var parsed = codec.Parse(message);
        var envelope = FeedPayloadReader.Read(message);
        byte[] payload = envelope.Payload.ToArray();
        edit(parsed.Fields, payload);
        return codec.Parse(new FeedMessage(message.Delivery, envelope.Serialize(payload)));
    }

    /// <summary>
    /// Replaces one character of a candidate's text in the payload.
    /// </summary>
    private static void Overwrite(byte[] payload, FeedField field, char from, char to)
    {
        int offset = Locate(payload, field.Value);
        payload[offset + field.Value.IndexOf(from)] = (byte)to;
    }

    /// <summary>
    /// Replaces the first character of a candidate's text in the payload.
    /// </summary>
    private static void OverwriteFirst(byte[] payload, FeedField field, char to) => payload[Locate(payload, field.Value)] = (byte)to;

    /// <summary>
    /// Finds a candidate's text in the payload.
    /// </summary>
    private static int Locate(byte[] payload, string value) => payload.AsSpan().IndexOf(Encoding.ASCII.GetBytes(value));

    /// <summary>
    /// Keeps the JSON layout of the original parse but uses edited field values, for anchor checks that never serialize.
    /// </summary>
    private static ParsedFeed StringLayout(ParsedFeed original, ParsedFeed edited) => new(edited.Fields, original.Layout);

    /// <summary>
    /// Requires an InvalidDataException whose message contains the expected text.
    /// </summary>
    private static async Task RejectAsync(Func<ValueTask<DetectionOutcome>> action, string expected, string label)
    {
        try
        {
            await action();
        }
        catch (InvalidDataException ex) when (ex.Message.Contains(expected, StringComparison.Ordinal))
        {
            Console.WriteLine("PASS " + label);
            return;
        }
        throw new Exception("Expected rejection: " + label);
    }

    /// <summary>
    /// Requires a condition.
    /// </summary>
    private static void Check(bool condition, string label)
    {
        if (!condition)
        {
            throw new Exception(label);
        }
    }

    #endregion
}
