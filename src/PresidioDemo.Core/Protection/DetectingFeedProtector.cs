using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PresidioDemo.Core.Models;

namespace PresidioDemo.Core.Protection;

#region Enumerations

/// <summary>
/// What happened to one decoded string; the explicit values keep the existing numeric values (1 was a removed decision).
/// </summary>
public enum DetectionDecision
{
    /// <summary>
    /// A format matched the whole string and masked it.
    /// </summary>
    Masked = 0,
    /// <summary>
    /// A keep matched; the string is published unchanged.
    /// </summary>
    Kept = 2,
    /// <summary>
    /// A scanned keep matched; personal-data spans inside it were masked.
    /// </summary>
    MaskedInside = 3,
    /// <summary>
    /// The string is a PNR anchor and is published unchanged (WR-017).
    /// </summary>
    Anchor = 4,
    /// <summary>
    /// No format or keep matched; the string is masked across its full width (WR-014).
    /// </summary>
    MaskedByDefault = 5,
    /// <summary>
    /// A keep matched but a detection below the threshold sits inside it: published, and worth reviewing.
    /// </summary>
    MissedBelowThreshold = 6
}

#endregion

#region Models

/// <summary>
/// One value-free detection log entry (WR-018): never the value, only its location, length, shape and decision.
/// </summary>
/// <param name="Slot">The candidate's order among the message's decoded strings.</param>
/// <param name="Length">The value length.</param>
/// <param name="Shape">The character shape: A for a letter, 9 for a digit, other characters unchanged.</param>
/// <param name="Format">The format or keep name, <c>anchor</c>, or <c>none</c>.</param>
/// <param name="Entity">The detected entity types, joined with <c>+</c>, or empty.</param>
/// <param name="Score">The highest detection score, or zero.</param>
/// <param name="Decision">What happened to the string.</param>
/// <param name="Offset">The payload byte offset of the string, or null when the codec reports none.</param>
public sealed record DetectionEvent(int Slot, int Length, string Shape, string Format, string Entity, double Score, DetectionDecision Decision,
    int? Offset = null);

/// <summary>
/// The protected values for every parsed field, and one detection event per decoded string.
/// </summary>
/// <param name="Values">The protected value of every field, by identifier.</param>
/// <param name="Events">The value-free detection events, in candidate order.</param>
/// <param name="CandidateValues">The decoded value of each candidate, by slot, kept beside the events so the events stay
/// value-free; written to the detection log only with <c>Presidio:DetectionLogValues</c> on (WR-020).</param>
/// <param name="ProtectedCandidateValues">The protected value of each candidate, by slot, for the after values of the
/// detection log under WR-020.</param>
public sealed record DetectionOutcome(IReadOnlyDictionary<string, string> Values, IReadOnlyList<DetectionEvent> Events,
    IReadOnlyList<string>? CandidateValues = null, IReadOnlyList<string>? ProtectedCandidateValues = null);

#endregion

/// <summary>
/// Protects one parsed message with its feed's recognizer set. Every decision is made here; Presidio only returns spans.
/// Order per string: PNR anchor, a declared format matching the whole string, keep pattern (scanned keeps mask inner
/// spans), a built-in matching the whole string, otherwise a full-width default mask (WR-014, WR-017, W-020). Every
/// protection keeps the string's width, so the binary framing stays valid (WR-015).
/// </summary>
/// <param name="sets">The validated recognizer sets by feed.</param>
public sealed class DetectingFeedProtector(IReadOnlyDictionary<FeedType, FeedRecognizerSet> sets) : IFeedProtector
{

    #region Fields and Constants

    /// <summary>
    /// Serializes calls into the shared embedded Python engines.
    /// </summary>
    private static readonly SemaphoreSlim EngineGate = new(1, 1);

    #endregion

    #region Methods

    /// <summary>
    /// Builds every feed's Presidio registry. Call once after <see cref="PythonHost.Start"/>.
    /// </summary>
    /// <exception cref="InvalidDataException">The bridge rejected a configuration.</exception>
    public void Configure()
    {
        foreach (var set in sets.Values)
        {
            try
            {
                PythonHost.Call("configure_feed", set.ToBridgeJson());
            }
            catch (Exception)
            {
                throw new InvalidDataException($"Local Presidio could not load the {FeedCatalog.Get(set.Feed).FolderName} recognizers.");
            }
        }
    }

    /// <summary>
    /// Protects every decoded string of one parsed message.
    /// </summary>
    /// <param name="feed">The feed route.</param>
    /// <param name="parsed">The parse from the generic XDR codec.</param>
    /// <param name="cancellationToken">The token that interrupts processing.</param>
    /// <returns>The protected value of every field and one event per decoded string.</returns>
    /// <exception cref="InvalidDataException">A structural failure: anchor missing or not PNR-shaped, or detection failed.</exception>
    public async ValueTask<DetectionOutcome> ProtectAsync(FeedType feed, ParsedFeed parsed, CancellationToken cancellationToken)
    {
        var set = sets[feed];
        var candidates = parsed.Fields;
        var values = parsed.Fields.ToDictionary(field => field.Id, field => field.Value, StringComparer.Ordinal);
        var events = new DetectionEvent?[candidates.Count];
        Anchoring anchors;
        try
        {
            anchors = Anchors(set, candidates);
            var pending = new List<int>();
            for (int slot = 0; slot < candidates.Count; slot++)
            {
                var field = candidates[slot];
                if (field.Value.Length == 0)
                {
                    events[slot] = Event(slot, field, "none", "", 0, DetectionDecision.Kept);
                }
                else if (anchors.Whole.Contains(slot))
                {
                    events[slot] = Event(slot, field, "anchor", "PNR", 1, DetectionDecision.Anchor);
                }
                else
                {
                    pending.Add(slot);
                }
            }

            var spans = await AnalyzeAsync(feed, pending.Select(slot => candidates[slot].Value).ToArray(), cancellationToken);
            for (int i = 0; i < pending.Count; i++)
            {
                int slot = pending[i];
                var field = candidates[slot];
                var found = spans[i];
                var strong = found.Where(span => span.Score >= set.Threshold).ToArray();
                var wholeSpans = strong.Where(span => span.Start == 0 && span.End == field.Value.Length).OrderByDescending(span => span.Score).ToArray();
                // A declared format that matches the whole value wins over a keep, so a keep never publishes a value the
                // feed's own formats identify (R-004); built-in and NER matches come after keeps, which are reviewed.
                var formatWhole = wholeSpans.FirstOrDefault(span => set.Formats.Any(format => format.Name == span.Recognizer));
                var keep = set.Keeps.FirstOrDefault(k => k.MatchesWhole(field.Value));
                if (formatWhole is not null || (keep is null && wholeSpans.Length > 0))
                {
                    var whole = formatWhole ?? wholeSpans[0];
                    var (mask, name) = Protection(set, whole);
                    values[field.Id] = new string(mask, field.Value.Length);
                    events[slot] = Event(slot, field, name, whole.Entity, whole.Score, DetectionDecision.Masked);
                }
                else if (keep is not null)
                {
                    var inside = keep.Scan ? strong : [];
                    anchors.Embedded.TryGetValue(slot, out var pnr);
                    values[field.Id] = MaskSpans(field.Value, inside, set, pnr);
                    var weak = keep.Scan ? found.Where(span => span.Score < set.Threshold && !inside.Any(s => s.Start <= span.Start && s.End >= span.End)).ToArray() : [];
                    var decision = inside.Length > 0 ? DetectionDecision.MaskedInside : weak.Length > 0 ? DetectionDecision.MissedBelowThreshold : DetectionDecision.Kept;
                    var reported = inside.Length > 0 ? inside : weak;
                    events[slot] = Event(slot, field, keep.Name, Entities(reported), reported.Select(s => s.Score).DefaultIfEmpty(0).Max(), decision);
                }
                else
                {
                    values[field.Id] = DefaultMask(field.Value, set.DefaultMaskCharacter);
                    events[slot] = Event(slot, field, "none", Entities(found), found.Select(s => s.Score).DefaultIfEmpty(0).Max(), DetectionDecision.MaskedByDefault);
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            throw new InvalidDataException("A recognizer pattern timed out; input retained and no output was published.");
        }

        var detected = events.Select(e => e!).ToArray();
        var candidateValues = candidates.Select(c => c.Value).ToArray();
        foreach (int slot in anchors.Whole)
        {
            if (values[candidates[slot].Id] != candidates[slot].Value)
            {
                throw new DetectionTrace(detected, candidateValues).Reject("Protection changed a PNR.");
            }
        }
        foreach (var (slot, (start, length)) in anchors.Embedded)
        {
            if (!values[candidates[slot].Id].AsSpan(start, length).SequenceEqual(candidates[slot].Value.AsSpan(start, length)))
            {
                throw new DetectionTrace(detected, candidateValues).Reject("Protection changed an embedded PNR.");
            }
        }
        return new DetectionOutcome(values, detected, candidateValues, candidates.Select(c => values[c.Id]).ToArray());
    }

    /// <summary>
    /// Returns the character shape of a value: A for a letter, 9 for a digit, other characters unchanged.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The shape, at most 64 characters.</returns>
    public static string Shape(string value)
    {
        var shape = new StringBuilder(Math.Min(value.Length, 64));
        foreach (char c in value.Take(64))
        {
            shape.Append(char.IsAsciiLetter(c) ? 'A' : char.IsAsciiDigit(c) ? '9' : char.IsAscii(c) && !char.IsControl(c) ? c : '?');
        }
        return shape.ToString();
    }

    /// <summary>
    /// Masks every character except literal <c>*</c> separators (WR-005, WR-014).
    /// </summary>
    /// <param name="value">The value.</param>
    /// <param name="mask">The mask character.</param>
    /// <returns>The masked value, same width.</returns>
    public static string DefaultMask(string value, char mask) => new(value.Select(c => c == '*' ? c : mask).ToArray());

    /// <summary>
    /// Finds every PNR anchor (WR-017). A required anchor that is missing, a value at an anchor position that is neither
    /// PNR-shaped nor a declared keep or format (a malformed PNR), and an embedded PNR that does not match its pattern
    /// are structural failures.
    /// </summary>
    /// <param name="set">The recognizer set.</param>
    /// <param name="candidates">The decoded strings.</param>
    /// <returns>The whole-string anchored slots and the embedded PNR ranges.</returns>
    /// <exception cref="InvalidDataException">An anchor is missing or malformed.</exception>
    private static Anchoring Anchors(FeedRecognizerSet set, IReadOnlyList<FeedField> candidates)
    {
        var whole = new HashSet<int>();
        var embedded = new Dictionary<int, (int Start, int Length)>();
        foreach (var anchor in set.Anchors)
        {
            int before = whole.Count + embedded.Count;
            if (anchor.Within is not null)
            {
                var keep = set.Keeps.Single(k => k.Name == anchor.Within);
                for (int slot = 0; slot < candidates.Count; slot++)
                {
                    if (!keep.MatchesWhole(candidates[slot].Value))
                    {
                        continue;
                    }
                    var group = anchor.Capture!.Match(candidates[slot].Value).Groups["pnr"];
                    if (!group.Success || !FeedRecognizerSet.PnrShape.IsMatch(group.Value))
                    {
                        throw new InvalidDataException("An embedded PNR is missing or not PNR-shaped; input retained and no output was published.");
                    }
                    embedded[slot] = (group.Index, group.Length);
                }
            }
            else
            {
                string neighbour = anchor.After ?? anchor.Before!;
                int index = Enumerable.Range(0, candidates.Count).FirstOrDefault(i => set.MatchesNamed(neighbour, candidates[i].Value), -1);
                int target = index < 0 ? -1 : anchor.After is not null ? index + anchor.Offset : index - anchor.Offset;
                if (target >= 0 && target < candidates.Count)
                {
                    string value = candidates[target].Value;
                    if (FeedRecognizerSet.PnrShape.IsMatch(value))
                    {
                        whole.Add(target);
                    }
                    else if (!anchor.Optional || !(set.Keeps.Any(k => k.MatchesWhole(value)) || set.Formats.Any(f => f.MatchesWhole(value))))
                    {
                        // An optional position may hold another declared value (no PNR present); anything else is a
                        // malformed PNR and must not be masked and published.
                        throw new InvalidDataException("The value at a PNR anchor position is not PNR-shaped; input retained and no output was published.");
                    }
                }
            }
            if (whole.Count + embedded.Count == before && !anchor.Optional)
            {
                throw new InvalidDataException("The PNR anchor is missing; input retained and no output was published.");
            }
        }
        return new Anchoring(whole, embedded);
    }

    /// <summary>
    /// Calls the Python bridge once for every pending string of the message.
    /// </summary>
    /// <param name="feed">The feed route.</param>
    /// <param name="texts">The strings to analyze.</param>
    /// <param name="cancellationToken">The token that interrupts waiting for the engine.</param>
    /// <returns>The spans per string.</returns>
    /// <exception cref="InvalidDataException">Detection failed.</exception>
    private static async ValueTask<IReadOnlyList<Span[]>> AnalyzeAsync(FeedType feed, IReadOnlyList<string> texts, CancellationToken cancellationToken)
    {
        if (texts.Count == 0)
        {
            return [];
        }
        string json;
        await EngineGate.WaitAsync(cancellationToken);
        try
        {
            json = PythonHost.Call("analyze_strings", FeedCatalog.Get(feed).FolderName, JsonSerializer.Serialize(texts));
        }
        catch (Exception)
        {
            throw new InvalidDataException("Local Presidio detection failed; input retained and no output was published.");
        }
        finally
        {
            EngineGate.Release();
        }

        using var document = JsonDocument.Parse(json);
        var result = document.RootElement.EnumerateArray().Select(found => found.EnumerateArray().Select(span => new Span(
            span[0].GetInt32(), span[1].GetInt32(), span[2].GetString() ?? "", span[3].GetDouble(), span[4].GetString() ?? "")).ToArray()).ToArray();
        if (result.Length != texts.Count || result.Zip(texts).Any(pair => pair.First.Any(s => s.Start < 0 || s.End > pair.Second.Length || s.Start >= s.End)))
        {
            throw new InvalidDataException("Local Presidio returned spans that do not fit the message; no output was published.");
        }
        return result;
    }

    /// <summary>
    /// Masks the given spans in place with each span's own mask character, so a kept value keeps its width, never
    /// touching an embedded PNR range.
    /// </summary>
    /// <param name="value">The kept value.</param>
    /// <param name="spans">The spans to protect.</param>
    /// <param name="set">The recognizer set.</param>
    /// <param name="pnr">An embedded PNR range to leave unchanged, or the default (empty) range.</param>
    /// <returns>The value with the spans protected.</returns>
    private static string MaskSpans(string value, IReadOnlyList<Span> spans, FeedRecognizerSet set, (int Start, int Length) pnr = default)
    {
        if (spans.Count == 0)
        {
            return value;
        }
        var masks = new char?[value.Length];
        foreach (var span in spans.OrderBy(s => s.Start).ThenByDescending(s => s.End))
        {
            char mask = Protection(set, span).Mask;
            for (int i = span.Start; i < span.End; i++)
            {
                if (i < pnr.Start || i >= pnr.Start + pnr.Length)
                {
                    masks[i] ??= mask;
                }
            }
        }
        return new string(value.Select((c, i) => masks[i] ?? c).ToArray());
    }

    /// <summary>
    /// Returns the mask character of the format or built-in that produced a span, and the name to log.
    /// </summary>
    /// <param name="set">The recognizer set.</param>
    /// <param name="span">The span.</param>
    /// <returns>The mask character and the name to log.</returns>
    private static (char Mask, string Name) Protection(FeedRecognizerSet set, Span span)
    {
        if (set.Formats.FirstOrDefault(f => f.Name == span.Recognizer) is { } format)
        {
            return (format.MaskCharacter, format.Name);
        }
        if (set.BuiltIns.FirstOrDefault(b => b.Entity == span.Entity) is { } builtIn)
        {
            return (builtIn.MaskCharacter, "builtIn:" + builtIn.Entity);
        }
        return (set.DefaultMaskCharacter, "builtIn:" + span.Entity);
    }

    /// <summary>
    /// Joins the distinct entity types of spans.
    /// </summary>
    private static string Entities(IEnumerable<Span> spans) => string.Join('+', spans.Select(s => s.Entity).Distinct().Order(StringComparer.Ordinal));

    /// <summary>
    /// Creates a value-free event, located by the string's payload offset (WR-018).
    /// </summary>
    private static DetectionEvent Event(int slot, FeedField field, string format, string entity, double score, DetectionDecision decision) =>
        new(slot, field.Value.Length, Shape(field.Value), format, entity, Math.Round(score, 2, MidpointRounding.AwayFromZero), decision, field.Offset);

    #endregion

    #region Nested Types

    /// <summary>
    /// The PNR anchors found in one message.
    /// </summary>
    /// <param name="Whole">Slots whose whole value is a PNR.</param>
    /// <param name="Embedded">Slots holding an embedded PNR, with its character range.</param>
    private sealed record Anchoring(HashSet<int> Whole, Dictionary<int, (int Start, int Length)> Embedded);

    /// <summary>
    /// One span returned by Presidio.
    /// </summary>
    /// <param name="Start">The first character.</param>
    /// <param name="End">The character after the last.</param>
    /// <param name="Entity">The entity type.</param>
    /// <param name="Score">The detection score.</param>
    /// <param name="Recognizer">The recognizer name: an XML format name or a built-in recognizer.</param>
    private sealed record Span(int Start, int End, string Entity, double Score, string Recognizer);

    #endregion
}
