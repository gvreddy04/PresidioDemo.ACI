using System.Buffers.Binary;
using System.Text;
using PresidioDemo.Core.Decoder;
using PresidioDemo.Core.Models;
using PresidioDemo.Core.Pipeline;
using PresidioDemo.Core.Protection;

/// <summary>
/// Checks the decoded-text protector (WR-014, WR-015): each decoded string is decided on its own, detected spans get their
/// entity's action fitted to width, a string in which nothing is detected is published unchanged and listed for review,
/// detection failures dead-letter, and every production sample rebuilds and validates.
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
        var files = RecognizerFileReader.ReadAll(recognizers);
        string samples = Path.Combine(projectRoot, "docs", "sample-docs");
        var protector = new DetectingFeedProtector(files);

        // Detection failure: the bridge has no registry for an unconfigured feed name, so the call fails and dead-letters.
        var unconfigured = new DetectingFeedProtector(new Dictionary<FeedType, RecognizerFile> { [FeedType.PNR] = files[FeedType.PNR] });
        await RejectAsync(() => unconfigured.ProtectAsync(FeedType.PNR, Parse(Path.Combine(samples, "PNR", "PNR.txt")), CancellationToken.None),
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
            Check(parsed.Fields.All(f => outcome.Values[f.Id].Length == f.Value.Length), Path.GetFileName(path) + ": every protected string keeps its width");
            var decoded = parsed.Fields
                .Select(f => f.Value).Where(v => v.Any(char.IsAsciiLetterOrDigit) && DetectingFeedProtector.Shape(v) != v).ToHashSet(StringComparer.Ordinal);
            Check(outcome.Events.All(e => !decoded.Contains(e.Shape) && !decoded.Contains(e.Recognizer) && !decoded.Contains(e.Entity)),
                Path.GetFileName(path) + ": no detection event field carries a decoded value");
            // WR-020: the decoded values travel beside the events, one per slot, for the values flag only.
            var candidateValues = parsed.Fields.Select(f => f.Value);
            Check(outcome.CandidateValues is { } carried && carried.Count == outcome.Events.Count && carried.SequenceEqual(candidateValues),
                Path.GetFileName(path) + ": the candidate values match the decoded strings by slot");
            // WR-018: a binary string is located by its payload offset only.
            var payload = FeedPayloadReader.Read(message).Payload;
            Check(outcome.Events.Zip(parsed.Fields).All(pair => pair.First.Offset is int at &&
                Encoding.ASCII.GetString(payload.AsSpan(at, pair.Second.Value.Length)) == pair.Second.Value), Path.GetFileName(path) + ": each binary event's offset leads to its value");
            published++;
        }
        Console.WriteLine($"PASS {published} production samples protected, rebuilt and validated with the recognizer files");

        // WR-018, WR-020: one block per message; every string in exactly one group; review lines carry a reason and a fix.
        DetectionEvent[] events =
        [
            new(0, 13, "AAAAAA/AAAAAA", "passengerName", "PERSON", 0.9, DetectionDecision.Changed, 0x01A4, "mask"),
            new(1, 6, "AAA999", "none", "", 0, DetectionDecision.NothingDetected, 0x0018, Reasons: ReviewReason.NothingDetected, Threshold: 0.5),
            new(2, 22, "AAAA AAA", DetectingFeedProtector.SpacyRecognizer, "LOCATION", 0.85, DetectionDecision.Changed, 0x0200, "mask", ReviewReason.SpacyGuess, 0.5),
            new(3, 6, "AA9999", "allow_list", "", 0, DetectionDecision.Allowed, 0x00E0),
            new(4, 10, "AA99999999", "UsLicenseRecognizer", "US_DRIVER_LICENSE", 0.3, DetectionDecision.BelowThreshold, 0x0288, Reasons: ReviewReason.BelowThreshold, Threshold: 0.5),
            new(5, 7, "99AAA99", "dateOfBirth", "DATE_OF_BIRTH", 0.9, DetectionDecision.Changed, 0x02A0, "mask"),
            new(6, 12, "AAAA AAAAAAA", "EmailRecognizer", "EMAIL_ADDRESS", 1, DetectionDecision.Changed, 0x02C0, "replace", ReviewReason.NoAction | ReviewReason.Cut, 0.5),
        ];
        string[] fictionalBefore = ["MILLER/JORDAN", "ABC123", "LINE ONE\nSAY \"HI\" \\ X", "XY1234", "XY99887766", "14MAR85", "CALL O'NEIL"];
        string[] fictionalAfter = ["######/######", "ABC123", "######################", "XY1234", "XY99887766", "*******", "CALL <EMAIL"];
        string[] Lines(string block) => block.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        string Section(string block, string heading)
        {
            var lines = Lines(block);
            int start = Array.FindIndex(lines, line => line == "  " + heading);
            int end = Array.FindIndex(lines, start + 1, line => !line.StartsWith("    ", StringComparison.Ordinal));
            return string.Join("\n", lines[(start + 1)..(end < 0 ? lines.Length : end)]);
        }
        const string ReviewHeading = "Review (check these; each line has a fix)";
        var log = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, events);
        var valued = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, events, before: fictionalBefore, after: fictionalAfter);
        Check(Lines(log)[0] == "PNR " + Guid.Empty.ToString("N") + " DETECTION PUBLISHED file=- fields=7 pii=2 non-pii=1 review=4 offsets=payload",
            "the header names the feed, transaction, outcome, file (- when none), field counts and offset base");
        Check(Lines(log).Skip(1).All(line => line.StartsWith(' ')) && Lines(valued).Skip(1).All(line => line.StartsWith(' ')),
            "every line after the header is indented, so a collector keeps the block as one entry");
        string pii = Section(log, "PII fields (changed)"), nonPii = Section(log, "Non-PII fields (unchanged)"), review = Section(log, ReviewHeading);
        Check(new[] { "@0x01A4", "@0x02A0" }.All(pii.Contains) && nonPii.Contains("@0x00E0", StringComparison.Ordinal)
            && new[] { "@0x0018", "@0x0200", "@0x0288", "@0x02C0" }.All(review.Contains), "each string is listed in its group, located by slot and offset");
        Check(Lines(log).Count(line => line.Contains(" @0x", StringComparison.Ordinal)) == events.Length, "each string appears exactly once");
        string ReviewLine(string at) => review.Split('\n').Single(line => line.Contains(at, StringComparison.Ordinal));
        Check(ReviewLine("@0x0018").Contains("  unchanged  ", StringComparison.Ordinal)
            && ReviewLine("@0x0018").Contains("reason=nothing-detected fix=\"add a recognizer if this is personal data, or an allow-list item if it is not\"", StringComparison.Ordinal),
            "a nothing-detected string is listed unchanged with its fix");
        Check(ReviewLine("@0x0288").Contains("score=0.30<0.50", StringComparison.Ordinal) && ReviewLine("@0x0288").Contains("reason=below-threshold", StringComparison.Ordinal),
            "a below-threshold string compares its score with the threshold");
        Check(ReviewLine("@0x0200").Contains("  changed  ", StringComparison.Ordinal) && ReviewLine("@0x0200").Contains("operator=mask decision=changed reason=spacy-guess", StringComparison.Ordinal),
            "a spaCy guess is listed for review although it changed the string");
        Check(ReviewLine("@0x02C0").Contains("reason=no-action+cut fix=\"add an <anonymizer> for EMAIL_ADDRESS; use mask for this entity, or a shorter new_value\"", StringComparison.Ordinal),
            "several reasons are listed with one fix each");
        Check(fictionalBefore.All(value => !log.Contains(value, StringComparison.Ordinal)) && fictionalAfter.Where(value => !value.All(c => c == '#')).All(value => !log.Contains(value, StringComparison.Ordinal))
            && !log.Contains("->", StringComparison.Ordinal) && log.Contains("len=13 shape=AAAAAA/AAAAAA", StringComparison.Ordinal),
            "a value-free block carries lengths and shapes, never a value");
        Check(Lines(valued).Length == Lines(log).Length, "an encoded value never breaks a line");
        Check(valued.Contains("\"MILLER/JORDAN\" -> \"######/######\"", StringComparison.Ordinal) && valued.Contains("\"CALL O'NEIL\" -> \"CALL <EMAIL\"", StringComparison.Ordinal)
            && Section(valued, "Non-PII fields (unchanged)").Contains("\"XY1234\"  recognizer=allow_list", StringComparison.Ordinal),
            "a changed string shows before -> after; an unchanged string shows its value once");
        string encoded = Lines(valued).Single(line => line.Contains("@0x0200", StringComparison.Ordinal));
        string quoted = encoded[(encoded.IndexOf('"', StringComparison.Ordinal))..encoded.IndexOf(" -> ", StringComparison.Ordinal)];
        Check(System.Text.Json.JsonSerializer.Deserialize<string>(quoted) == fictionalBefore[2], "an encoded value reads back exactly");
        var rejected = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, events, "Fixture rejection.", fictionalBefore, null);
        Check(Lines(rejected)[0].EndsWith(" DETECTION DEAD-LETTERED file=- fields=7 pii=2 non-pii=1 review=4 offsets=payload reason=\"Fixture rejection.\"", StringComparison.Ordinal)
            && rejected.Contains("\"MILLER/JORDAN\" -> not published", StringComparison.Ordinal), "a dead-lettered block gives the reason and no after value");
        var allowedOnly = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, [events[3]]);
        Check(Section(allowedOnly, "PII fields (changed)") == "    (none)" && Section(allowedOnly, ReviewHeading) == "    (none)",
            "an empty group is printed as (none)");
        // Review R-003: fewer values than events must not fail; a slot without a value keeps the value-free form.
        var shortValues = PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, Guid.Empty, events, before: ["MILLER/JORDAN"], after: fictionalAfter);
        Check(shortValues.Contains("\"MILLER/JORDAN\" -> \"######/######\"", StringComparison.Ordinal) && shortValues.Contains("len=6 shape=AAA999", StringComparison.Ordinal),
            "a slot without a value keeps the value-free form");
        // Review R-010: zero-width and bidirectional formatting characters are escaped, and the value still reads back.
        string disguised = "CALL " + (char)0x202E + "MILLER" + (char)0x200B + " HOME";
        string encodedDisguise = PresidioDemo.Core.Logging.DetectionLog.Encode(disguised);
        Check(!encodedDisguise.Contains((char)0x202E) && !encodedDisguise.Contains((char)0x200B) && encodedDisguise.Contains("\\u202E", StringComparison.Ordinal)
            && System.Text.Json.JsonSerializer.Deserialize<string>(encodedDisguise) == disguised, "formatting characters are escaped and the value reads back");
        Check(PresidioDemo.Core.Logging.DetectionLog.Encode("O'NEIL" + (char)0x2028 + "X") == "\"O'NEIL\\u2028X\"", "an apostrophe stays readable and a line separator is escaped");
        // Review R-011: the worker writes each block with one Console.Out.Write. Console.Out is a synchronized writer, so
        // blocks written from many threads at once (as by several consumers per task) must come out whole.
        Check(Console.Out.GetType().Name == "SyncTextWriter", "the console writer the worker uses is synchronized");
        var captured = new StringWriter();
        var console = Console.Out;
        Console.SetOut(TextWriter.Synchronized(captured));
        try
        {
            Parallel.For(0, 400, new ParallelOptions { MaxDegreeOfParallelism = 16 }, i =>
                Console.Out.Write(PresidioDemo.Core.Logging.DetectionLog.FormatBlock(FeedType.PNR, new Guid(i, 0, 0, new byte[8]), events, before: fictionalBefore, after: fictionalAfter)));
        }
        finally
        {
            Console.SetOut(console);
        }
        var written = Lines(captured.ToString());
        int perBlock = Lines(valued).Length;
        // "PNR " plus the 32-digit transaction and a space: the rest of each header, and every body line, must match.
        const int afterTransaction = 37;
        Check(written.Length == 400 * perBlock && Enumerable.Range(0, 400).All(b =>
            written[b * perBlock][afterTransaction..] == Lines(valued)[0][afterTransaction..]
            && written.Skip(b * perBlock + 1).Take(perBlock - 1).SequenceEqual(Lines(valued).Skip(1))),
            "400 blocks written from 16 threads at once each come out whole");
        Console.WriteLine("PASS the detection log writes one grouped block per message, with a fix per review line and values only when passed (WR-018, WR-020)");

        // WR-014 on the shipped file: declared recognizers act, allowed strings and undetected strings stay unchanged.
        string pnrSample = Path.Combine(samples, "PNR", "PNR.txt");
        var pnrOutcome = await protector.ProtectAsync(FeedType.PNR, Parse(pnrSample), CancellationToken.None);
        Check(pnrOutcome.Events.Any(e => e.Decision == DetectionDecision.Changed) && pnrOutcome.Events.Any(e => e.Decision == DetectionDecision.Allowed)
            && pnrOutcome.Events.Any(e => e.Decision == DetectionDecision.NothingDetected), "PNR.txt has changed, allowed and undetected strings");
        Check(pnrOutcome.Events.Where(e => e.Decision is DetectionDecision.Allowed or DetectionDecision.NothingDetected or DetectionDecision.BelowThreshold)
            .All(e => pnrOutcome.Values[Parse(pnrSample).Fields[e.Slot].Id] == Parse(pnrSample).Fields[e.Slot].Value), "allowed and undetected strings are published unchanged");
        // AC-011: no PNR anchor; a message whose creation time is gone still publishes.
        var noCreationTime = ParseEdited(pnrSample, FeedType.PNR, (fields, payload) =>
            OverwriteFirst(payload, fields.First(f => f.Value.Length == 9 && f.Value.All(char.IsAsciiDigit)), 'A'));
        var stillPublished = await protector.ProtectAsync(FeedType.PNR, noCreationTime, CancellationToken.None);
        Check(stillPublished.Events.Count == noCreationTime.Fields.Count, "a message without a creation time is protected, not dead-lettered");

        // Made-up strings through the shipped file (AC-004, AC-005, AC-013).
        var shipped = await ProtectStringsAsync(protector, "MILLER/JORDAN MR", "Please book a window seat", "1405", "RBY09NOV*APPR CC VI 1234 OK",
            "Contact Alex Sample", "DOCSDAHK1/P/USA/X1234567/USA/12MAR85/F/09NOV31/MILLER/JORDAN");
        Check(shipped[0] == "****************", "a declared recognizer masks MILLER/JORDAN MR");
        Check(shipped[1] == "Please book a window seat", "a string in which nothing is detected is published unchanged");
        Check(shipped[2] == "1405", "a whole-string allow-list item keeps 1405");
        Check(shipped[3] == "RBY09NOV*APPR CC VI **** OK", "an allow-list item never releases a detected piece inside a longer string");
        Check(shipped[4] == "Contact ***********", "Presidio's PERSON is masked by the PERSON anonymizer");
        Check(!shipped[5].Contains("12MAR85", StringComparison.Ordinal) && !shipped[5].Contains("09NOV31", StringComparison.Ordinal)
            && shipped[5].StartsWith("DOCSDAHK1/P/", StringComparison.Ordinal), "a DOCS birth date and expiry are masked although they look like allowed dates");
        Console.WriteLine("PASS the shipped file acts per string: declared recognizers, allow list, unchanged when nothing is detected");

        // AC-003, AC-006, AC-008: test-only files reconfigure the PNR registry, so the shipped one is restored afterwards.
        string Temporary(string content)
        {
            string file = Path.Combine(Path.GetTempPath(), "pnr-" + Guid.NewGuid().ToString("N") + ".xml");
            File.WriteAllText(file, content);
            return file;
        }
        DetectingFeedProtector Configured(string file)
        {
            var configured = new DetectingFeedProtector(new Dictionary<FeedType, RecognizerFile> { [FeedType.PNR] = RecognizerFileReader.Read(file, FeedType.PNR) });
            configured.Configure();
            return configured;
        }
        string empty = Temporary("<recognizers feed=\"PNR\" />");
        string noCards = Temporary("<recognizers feed=\"PNR\"><recognizer name=\"CreditCardRecognizer\" type=\"predefined\" enabled=\"false\" />"
            + "<anonymizer entity=\"PERSON\" type=\"mask\" /></recognizers>");
        string withDefault = Temporary("<recognizers feed=\"PNR\"><anonymizer entity=\"PERSON\" type=\"mask\" /><anonymizer entity=\"DEFAULT\" type=\"mask\" /></recognizers>");
        try
        {
            var bare = await ProtectStringsAsync(Configured(empty), "Please book a window seat", "Contact Alex Sample", "alex@example.com", "Card 4111 1111 1111 1111");
            Check(bare[0] == "Please book a window seat", "an emptied file starts and publishes an undetected string unchanged");
            Check(bare[1] == "Contact <PERSON>   " && bare[2] == "<EMAIL_ADDRESS> " && bare[3] == "Card " + "<CREDIT_CARD>".PadRight(19),
                "with nothing configured Presidio's predefined recognizers detect, and replace is fitted to width");
            var switchedOff = await ProtectStringsAsync(Configured(noCards), "Card 4111 1111 1111 1111", "Contact Alex Sample", "alex@example.com");
            Check(switchedOff[0] == "Card 4111 1111 1111 1111", "a predefined recognizer switched off detects nothing");
            Check(switchedOff[1] == "Contact ***********" && switchedOff[2] == "<EMAIL_ADDRESS> ", "an entity uses its own anonymizer, else replace");
            var fallback = await ProtectStringsAsync(Configured(withDefault), "alex@example.com");
            Check(fallback[0] == "****************", "an entity without its own anonymizer uses DEFAULT");
            Console.WriteLine("PASS an emptied file runs Presidio's defaults; switches and anonymizers change the output with no code change");
        }
        finally
        {
            File.Delete(empty);
            File.Delete(noCards);
            File.Delete(withDefault);
            protector.Configure();
        }

        // WR-020: a rejection after detection keeps its events and values, with the reason unchanged. A codec whose
        // rebuild check fails stands in for a rebuild that differs outside the protected strings (WR-016).
        var failingRebuild = FeedWorkflowRouter.Create(protector, _ => new RebuildRejectingCodec(new PnrDecoder()));
        var afterDetection = await new FeedMessageProcessor(failingRebuild)
            .ProcessAsync(FeedType.PNR, Guid.NewGuid(), "PNR.txt", File.ReadAllBytes(pnrSample), CancellationToken.None);
        Check(!afterDetection.Published && afterDetection.Reason == RebuildRejectingCodec.Reason
            && afterDetection.DetectionEvents is { Count: > 0 } kept && afterDetection.DetectionValues?.Count == kept.Count,
            "a message dead-lettered after detection keeps its events and values, with the same reason");
        Console.WriteLine("PASS a message dead-lettered after detection keeps its events and values for the detection log (WR-020)");

        // WR-020: a message rejected before detection has no events to log.
        var reviewed = new FeedMessageProcessor(FeedPipelineConfiguration.Load(recognizers).CreateRouter(protector));
        var before = await reviewed.ProcessAsync(FeedType.PNR, Guid.NewGuid(), "truncated.bin", new byte[] { 0, 0, 0 }, CancellationToken.None);
        Check(!before.Published && before.DetectionEvents is null && before.DetectionValues is null, "truncated.bin: rejected before detection, so nothing to log");
        Console.WriteLine("PASS messages rejected before detection carry no events or values");

        // R-003: a recognizer pattern that times out dead-letters instead of publishing unchecked text. This reconfigures
        // the PNR registry, so it restores the shipped configuration afterwards.
        string slow = Temporary(File.ReadAllText(Path.Combine(recognizers, "pnr.xml")).Replace("</recognizers>",
            "<recognizer name=\"slowCheck\" type=\"custom\" supported_entity=\"DEMO_CODE\"><pattern name=\"slow\" score=\"0.85\">(A|AA)+$</pattern></recognizer></recognizers>",
            StringComparison.Ordinal));
        try
        {
            var slowProtector = Configured(slow);
            var slowInput = ParseEdited(pnrSample, FeedType.PNR, (fields, payload) =>
            {
                var target = fields.First(f => f.Value.Length >= 30 && f.Value.All(c => c is >= ' ' and <= '~'));
                Encoding.ASCII.GetBytes(new string('A', target.Value.Length - 1) + "!").CopyTo(payload, Locate(payload, target.Value));
            });
            await RejectAsync(() => slowProtector.ProtectAsync(FeedType.PNR, slowInput, CancellationToken.None),
                "Local Presidio detection failed", "a pattern timeout dead-letters the message");
        }
        finally
        {
            File.Delete(slow);
            protector.Configure();
        }

        // V-12: raw words such as numeric IDs are never decoded or changed, so a message whose raw word differs is
        // published with that word exactly as received.
        var pnrCodec = new PnrDecoder();
        var pnrMessage = Message(pnrSample, FeedType.PNR);
        var pnrEnvelope = FeedPayloadReader.Read(pnrMessage);
        var pnrCandidates = XdrFeedDecoder.Candidates(pnrCodec.Parse(pnrMessage));
        int firstEnd = pnrCandidates[0].Offset + pnrCandidates[0].Length;
        int rawWord = Enumerable.Range(0, pnrEnvelope.Payload.Length / 4).Select(i => i * 4)
            .First(o => o > firstEnd && !pnrCandidates.Any(c => o + 4 > c.Offset - 4 && o < c.Offset + c.Length + 4) &&
                BinaryPrimitives.ReadUInt32BigEndian(pnrEnvelope.Payload.AsSpan(o, 4)) is > 1 and < 100_000_000);
        byte[] mismatched = pnrEnvelope.Payload.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(mismatched.AsSpan(rawWord, 4), BinaryPrimitives.ReadUInt32BigEndian(mismatched.AsSpan(rawWord, 4)) + 1);
        var mismatchMessage = new FeedMessage(pnrMessage.Delivery, pnrEnvelope.Serialize(mismatched));
        var mismatchParsed = pnrCodec.Parse(mismatchMessage);
        var mismatchOutcome = await protector.ProtectAsync(FeedType.PNR, mismatchParsed, CancellationToken.None);
        byte[] mismatchOutput = pnrCodec.Serialize(mismatchParsed, mismatchOutcome.Values);
        pnrCodec.Validate(mismatchParsed, mismatchOutput);
        Check(FeedPayloadReader.Read(new FeedMessage(pnrMessage.Delivery, mismatchOutput)).Payload.AsSpan(rawWord, 4).SequenceEqual(mismatched.AsSpan(rawWord, 4)),
            "PNR raw word published unchanged");
        Console.WriteLine("PASS a PNR message with a changed raw word is published with the word unchanged");

        // WR-019: narrowing a recognizer adds parity misses against the frozen baseline. This reconfigures the PNR
        // registry, so it runs last and restores the shipped configuration afterwards.
        string narrowed = Temporary(File.ReadAllText(Path.Combine(recognizers, "pnr.xml"))
            .Replace("(?&lt;![A-Z])[A-Z]{2,}(?:[ '-][A-Z]+)*/[A-Z]*(?:[ '-][A-Z]+)*", "(?&lt;![A-Z])[A-Z]{30,}/[A-Z]{30,}", StringComparison.Ordinal));
        try
        {
            int reviewedMisses = await ParityMissesAsync(protector, projectRoot, FeedType.PNR);
            int narrowedMisses = await ParityMissesAsync(Configured(narrowed), projectRoot, FeedType.PNR);
            Check(narrowedMisses > reviewedMisses, "a narrowed name recognizer must add parity misses");
            Console.WriteLine($"PASS a narrowed PNR name recognizer adds parity misses ({reviewedMisses} -> {narrowedMisses} unapproved misses)");
        }
        finally
        {
            File.Delete(narrowed);
            protector.Configure();
        }
    }

    /// <summary>
    /// Protects made-up strings as one parsed message and returns the published values in order.
    /// </summary>
    private static async Task<string[]> ProtectStringsAsync(DetectingFeedProtector protector, params string[] values)
    {
        var parsed = new ParsedFeed(values.Select((value, i) => new FeedField(i.ToString(System.Globalization.CultureInfo.InvariantCulture), "slot" + i, value)).ToArray(), new object());
        var outcome = await protector.ProtectAsync(FeedType.PNR, parsed, CancellationToken.None);
        return parsed.Fields.Select(f => outcome.Values[f.Id]).ToArray();
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
    private static IFeedCodec Codec(FeedType feed) => FeedCodecRegistry.Create(feed);

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
    /// Replaces the first character of a candidate's text in the payload.
    /// </summary>
    private static void OverwriteFirst(byte[] payload, FeedField field, char to) => payload[Locate(payload, field.Value)] = (byte)to;

    /// <summary>
    /// Finds a candidate's text in the payload.
    /// </summary>
    private static int Locate(byte[] payload, string value) => payload.AsSpan().IndexOf(Encoding.ASCII.GetBytes(value));

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

/// <summary>
/// Wraps a real codec but fails its rebuild check, so a message is rejected after detection ran.
/// </summary>
/// <param name="inner">The codec that parses and rebuilds the message.</param>
internal sealed class RebuildRejectingCodec(IFeedCodec inner) : IFeedCodec
{

    #region Fields and Constants

    /// <summary>
    /// The value-free reason the rebuild check gives.
    /// </summary>
    public const string Reason = "Fixture rebuild check failed.";

    #endregion

    #region Methods

    /// <summary>
    /// Parses the message with the wrapped codec.
    /// </summary>
    /// <param name="message">The complete input delivery and its retained message bytes.</param>
    /// <returns>The wrapped codec's parse.</returns>
    public ParsedFeed Parse(FeedMessage message) => inner.Parse(message);

    /// <summary>
    /// Rebuilds the message with the wrapped codec.
    /// </summary>
    /// <param name="original">The original parse.</param>
    /// <param name="anonymizedFields">The protected values by field identifier.</param>
    /// <returns>The rebuilt message.</returns>
    public byte[] Serialize(ParsedFeed original, IReadOnlyDictionary<string, string> anonymizedFields) => inner.Serialize(original, anonymizedFields);

    /// <summary>
    /// Always rejects the rebuilt message.
    /// </summary>
    /// <param name="original">The original parse.</param>
    /// <param name="serialized">The rebuilt message.</param>
    /// <exception cref="InvalidDataException">Always.</exception>
    public void Validate(ParsedFeed original, ReadOnlyMemory<byte> serialized) => throw new InvalidDataException(Reason);

    #endregion
}
