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
        var unconfigured = new DetectingFeedProtector(new Dictionary<FeedType, FeedRecognizerSet> { [FeedType.PNR] = sets[FeedType.PNR] });
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
            var anchors = outcome.Events.Where(e => e.Decision == DetectionDecision.Anchor).ToArray();
            Check(anchors.Length > 0, Path.GetFileName(path) + ": a PNR anchor was found");
            var decoded = parsed.Fields
                .Select(f => f.Value).Where(v => v.Any(char.IsAsciiLetterOrDigit) && DetectingFeedProtector.Shape(v) != v).ToHashSet(StringComparer.Ordinal);
            Check(outcome.Events.All(e => !decoded.Contains(e.Shape) && !decoded.Contains(e.Format) && !decoded.Contains(e.Entity)),
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
        Console.WriteLine($"PASS {published} production samples protected, rebuilt and validated with the recognizer sets");

        // WR-018, WR-020: one block per message; every string in exactly one group; values only when passed, JSON-encoded.
        DetectionEvent[] events =
        [
            new(0, 13, "AAAAAA/AAAAAA", "passengerName", "PERSON", 0.9, DetectionDecision.Masked, 0x01A4),
            new(1, 6, "AAA999", "anchor", "PNR", 1, DetectionDecision.Anchor, 0x0018),
            new(2, 22, "AAAA AAA", "none", "", 0, DetectionDecision.MaskedByDefault, 0x0200),
            new(3, 6, "AA9999", "flightNumber", "", 0, DetectionDecision.Kept, 0x00E0),
            new(4, 10, "AA99999999", "loyalty", "LOYALTY", 0.3, DetectionDecision.MissedBelowThreshold, 0x0288),
            new(5, 7, "99AAA99", "dob", "DATE_OF_BIRTH", 1, DetectionDecision.Masked, 0x02A0),
            new(6, 12, "AAAA AAAAAAA", "remark", "PERSON", 0.85, DetectionDecision.MaskedInside, 0x02C0),
        ];
        string[] fictionalBefore = ["MILLER/JORDAN", "ABC123", "LINE ONE\nSAY \"HI\" \\ X", "XY1234", "XY99887766", "14MAR85", "CALL O'NEIL"];
        string[] fictionalAfter = ["######/######", "ABC123", "######################", "XY1234", "XY99887766", "*******", "CALL ######"];
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
        Console.WriteLine("PASS the detection log writes one grouped block per message, with values only when passed (WR-018, WR-020)");

        // V-06: a removed neighbour or a PNR that is no longer PNR-shaped dead-letters the message.
        string pnrSample = Path.Combine(samples, "PNR", "PNR.txt");
        await RejectAsync(() => protector.ProtectAsync(FeedType.PNR, ParseEdited(pnrSample, FeedType.PNR, (fields, payload) =>
            OverwriteFirst(payload, fields.First(f => f.Value.Length == 9 && f.Value.All(char.IsAsciiDigit)), 'A')), CancellationToken.None),
            "PNR anchor is missing", "a missing creation-time neighbour dead-letters PNR");
        await RejectAsync(() => protector.ProtectAsync(FeedType.PNR, ParseEdited(pnrSample, FeedType.PNR, (fields, payload) =>
        {
            int timeSlot = fields.ToList().FindIndex(f => f.Value.Length == 9 && f.Value.All(char.IsAsciiDigit));
            OverwriteFirst(payload, fields[timeSlot + 1], '-');
        }), CancellationToken.None), "anchor position is not PNR-shaped", "a PNR that is not PNR-shaped dead-letters PNR");

        // Unmatched strings are masked across their full width, keeping literal * separators (WR-014).
        Check(DetectingFeedProtector.DefaultMask("Q7 ZZ*AB", '#') == "#####*##", "default mask keeps width and literal *");
        var pnrOutcome = await protector.ProtectAsync(FeedType.PNR, Parse(pnrSample), CancellationToken.None);
        Check(pnrOutcome.Events.Count(e => e.Decision == DetectionDecision.Anchor) == 1, "PNR.txt has exactly one anchored PNR");
        Check(pnrOutcome.Events.Any(e => e.Decision == DetectionDecision.MaskedByDefault) && pnrOutcome.Events.Any(e => e.Decision == DetectionDecision.Masked),
            "PNR.txt masks declared formats and unmatched strings");
        Console.WriteLine("PASS PNR anchors fail closed and unmatched strings are masked by default");

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
        // the PNR registry, so it restores the reviewed configuration afterwards.
        string slow = Path.Combine(Path.GetTempPath(), "slow-pnr-" + Guid.NewGuid().ToString("N") + ".xml");
        File.WriteAllText(slow, File.ReadAllText(Path.Combine(recognizers, "pnr.xml"))
            .Replace("<keep name=\"docsRecord\"", "<format name=\"slowCheck\" entity=\"DEMO_CODE\"><pattern>(A|AA)+$</pattern></format>\n  <keep name=\"docsRecord\"", StringComparison.Ordinal));
        try
        {
            var slowSets = sets.ToDictionary(pair => pair.Key, pair => pair.Value);
            slowSets[FeedType.PNR] = RecognizerConfiguration.LoadFile(slow, FeedType.PNR);
            var slowProtector = new DetectingFeedProtector(slowSets);
            slowProtector.Configure();
            var slowInput = ParseEdited(pnrSample, FeedType.PNR, (fields, payload) =>
            {
                var target = fields.First(f => f.Value.Length >= 30 && f.Value.All(c => c is >= ' ' and <= '~'));
                Encoding.ASCII.GetBytes(new string('A', target.Value.Length - 1) + "!").CopyTo(payload, Locate(payload, target.Value));
            });
            await RejectAnyAsync(() => slowProtector.ProtectAsync(FeedType.PNR, slowInput, CancellationToken.None),
                ["Local Presidio detection failed", "A recognizer pattern timed out"], "a pattern timeout dead-letters the message");
        }
        finally
        {
            File.Delete(slow);
            protector.Configure();
        }

        // V-12, W-017: raw words such as numeric IDs are never decoded or changed, so a message whose raw word differs is
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
    private static Task RejectAsync(Func<ValueTask<DetectionOutcome>> action, string expected, string label) => RejectAnyAsync(action, [expected], label);

    /// <summary>
    /// Requires an InvalidDataException whose message contains one of the expected texts.
    /// </summary>
    private static async Task RejectAnyAsync(Func<ValueTask<DetectionOutcome>> action, string[] expected, string label)
    {
        try
        {
            await action();
        }
        catch (InvalidDataException ex) when (expected.Any(text => ex.Message.Contains(text, StringComparison.Ordinal)))
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
