using System.Text;
using System.Text.Json;
using PresidioDemo.Core.Models;

namespace PresidioDemo.Core.Protection;

#region Enumerations

/// <summary>
/// What happened to one decoded string (WR-014).
/// </summary>
public enum DetectionDecision
{
    /// <summary>
    /// A configured action changed at least one detected span.
    /// </summary>
    Changed = 0,
    /// <summary>
    /// Spans were detected, but their actions (such as <c>keep</c>) left the string unchanged.
    /// </summary>
    Kept = 1,
    /// <summary>
    /// The whole string matched an allow-list item and was published unchanged without analysis.
    /// </summary>
    Allowed = 2,
    /// <summary>
    /// Nothing was detected; the string is published unchanged.
    /// </summary>
    NothingDetected = 3,
    /// <summary>
    /// Only detections below the threshold were found; the string is published unchanged.
    /// </summary>
    BelowThreshold = 4
}

/// <summary>
/// Why a decoded string is listed for review in the detection log (WR-018); a string may have several reasons.
/// </summary>
[Flags]
public enum ReviewReason
{
    /// <summary>
    /// Not for review.
    /// </summary>
    None = 0,
    /// <summary>
    /// Published unchanged because nothing was detected.
    /// </summary>
    NothingDetected = 1,
    /// <summary>
    /// Published unchanged because every detection scored below the threshold.
    /// </summary>
    BelowThreshold = 2,
    /// <summary>
    /// Changed by an entity with no anonymizer of its own, so <c>DEFAULT</c> or Presidio's <c>replace</c> applied.
    /// </summary>
    NoAction = 4,
    /// <summary>
    /// Changed by a guess of the spaCy named-entity recognizer.
    /// </summary>
    SpacyGuess = 8,
    /// <summary>
    /// Detections of different entities overlapped; the higher score won the shared characters.
    /// </summary>
    Overlap = 16,
    /// <summary>
    /// An action's result was longer than the text it replaced and was cut to fit (WR-015).
    /// </summary>
    Cut = 32
}

#endregion

#region Models

/// <summary>
/// One value-free detection log entry (WR-018): never the value, only its location, length, shape and decision.
/// </summary>
/// <param name="Slot">The candidate's order among the message's decoded strings.</param>
/// <param name="Length">The value length.</param>
/// <param name="Shape">The character shape: A for a letter, 9 for a digit, other characters unchanged.</param>
/// <param name="Recognizer">The recognizer names joined with <c>+</c>, <c>allow_list</c>, or <c>none</c>.</param>
/// <param name="Entity">The detected entity types, joined with <c>+</c>, or empty.</param>
/// <param name="Score">The highest detection score, or zero.</param>
/// <param name="Decision">What happened to the string.</param>
/// <param name="Offset">The payload byte offset of the string, or null when the codec reports none.</param>
/// <param name="Operator">The operators applied, joined with <c>+</c>, or empty.</param>
/// <param name="Reasons">Why the string is listed for review, or <see cref="ReviewReason.None"/>.</param>
/// <param name="Threshold">The feed's score threshold, so a review line can compare a weak score with it.</param>
public sealed record DetectionEvent(int Slot, int Length, string Shape, string Recognizer, string Entity, double Score, DetectionDecision Decision,
    int? Offset = null, string Operator = "", ReviewReason Reasons = ReviewReason.None, double Threshold = 0);

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
/// Protects one parsed message with its feed's recognizer file. Presidio only returns spans; every decision is made here.
/// Each decoded string is decided on its own (WR-014): a whole-string allow-list match is published unchanged; otherwise
/// each span at or above the threshold gets its entity's action (its own, else <c>DEFAULT</c>, else <c>replace</c>), and a
/// string in which nothing is detected is published unchanged. Every result keeps the string's width (WR-015).
/// </summary>
/// <param name="files">The validated recognizer files by feed.</param>
public sealed class DetectingFeedProtector(IReadOnlyDictionary<FeedType, RecognizerFile> files) : IFeedProtector
{

    #region Fields and Constants

    /// <summary>
    /// The name Presidio reports for its spaCy named-entity recognizer.
    /// </summary>
    public const string SpacyRecognizer = "SpacyRecognizer";

    /// <summary>
    /// Serializes calls into the shared embedded Python engines.
    /// </summary>
    private static readonly SemaphoreSlim EngineGate = new(1, 1);

    #endregion

    #region Methods

    /// <summary>
    /// Builds every feed's Presidio registry. Call once after <see cref="PythonHost.Start"/>.
    /// </summary>
    /// <exception cref="InvalidDataException">The bridge rejected a configuration, such as an unknown predefined recognizer.</exception>
    public void Configure()
    {
        foreach (var file in files.Values)
        {
            try
            {
                PythonHost.Call("configure_feed", file.ToBridgeJson());
            }
            catch (Exception)
            {
                throw new InvalidDataException($"Local Presidio could not load the {FeedCatalog.Get(file.Feed).FolderName} recognizers.");
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
    /// <exception cref="InvalidDataException">Detection failed, a pattern timed out, or an action failed.</exception>
    public async ValueTask<DetectionOutcome> ProtectAsync(FeedType feed, ParsedFeed parsed, CancellationToken cancellationToken)
    {
        var file = files[feed];
        var candidates = parsed.Fields;
        var values = parsed.Fields.ToDictionary(field => field.Id, field => field.Value, StringComparer.Ordinal);
        var events = new DetectionEvent[candidates.Count];
        var pending = new List<int>();
        try
        {
            for (int slot = 0; slot < candidates.Count; slot++)
            {
                var field = candidates[slot];
                if (field.Value.Length == 0)
                {
                    events[slot] = Event(file, slot, field, "none", "", 0, DetectionDecision.NothingDetected);
                }
                else if (file.AllowList.MatchesWhole(field.Value))
                {
                    events[slot] = Event(file, slot, field, "allow_list", "", 0, DetectionDecision.Allowed);
                }
                else
                {
                    pending.Add(slot);
                }
            }
        }
        catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
        {
            throw new InvalidDataException("An allow-list pattern timed out; input retained and no output was published.");
        }

        var spans = await AnalyzeAsync(feed, pending.Select(slot => candidates[slot].Value).ToArray(), cancellationToken);
        for (int i = 0; i < pending.Count; i++)
        {
            int slot = pending[i];
            var field = candidates[slot];
            var strong = spans[i].Where(span => span.Score >= file.Threshold).ToArray();
            if (strong.Length == 0)
            {
                var weak = spans[i];
                events[slot] = weak.Length == 0
                    ? Event(file, slot, field, "none", "", 0, DetectionDecision.NothingDetected, reasons: ReviewReason.NothingDetected)
                    : Event(file, slot, field, Names(weak.Select(s => s.Recognizer)), Names(weak.Select(s => s.Entity)), weak.Max(s => s.Score),
                        DetectionDecision.BelowThreshold, reasons: ReviewReason.BelowThreshold);
                continue;
            }
            var (value, applied, reasons) = Apply(file, field.Value, strong);
            values[field.Id] = value;
            events[slot] = Event(file, slot, field, Names(applied.Select(a => a.Span.Recognizer)), Names(applied.Select(a => a.Span.Entity)),
                applied.Max(a => a.Span.Score), value == field.Value ? DetectionDecision.Kept : DetectionDecision.Changed,
                Names(applied.Select(a => Operator(a.Action.Operator))), reasons);
        }

        var detected = events.ToArray();
        return new DetectionOutcome(values, detected, candidates.Select(c => c.Value).ToArray(), candidates.Select(c => values[c.Id]).ToArray());
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
    /// Returns an operator's Presidio name.
    /// </summary>
    /// <param name="op">The operator.</param>
    /// <returns>Such as <c>mask</c>.</returns>
    public static string Operator(AnonymizerOperator op) => FeedAnonymizer.Operators.Single(pair => pair.Value == op).Key;

    /// <summary>
    /// Applies the configured actions to the detected spans of one string. Overlaps are resolved by score, then length,
    /// then position: each character belongs to the first span that claims it, and a span keeps the characters no
    /// higher-ranked span took; every contiguous run of a span's characters gets that span's action, fitted to its width.
    /// </summary>
    private static (string Value, IReadOnlyList<(Span Span, AnonymizerAction Action)> Applied, ReviewReason Reasons) Apply(RecognizerFile file, string value,
        IReadOnlyList<Span> spans)
    {
        var ranked = spans.OrderByDescending(s => s.Score).ThenByDescending(s => s.End - s.Start).ThenBy(s => s.Start)
            .ThenBy(s => s.Entity, StringComparer.Ordinal).ToArray();
        var owner = Enumerable.Repeat(-1, value.Length).ToArray();
        var reasons = ReviewReason.None;
        for (int rank = 0; rank < ranked.Length; rank++)
        {
            var span = ranked[rank];
            for (int c = span.Start; c < span.End; c++)
            {
                if (owner[c] < 0)
                {
                    owner[c] = rank;
                }
                else if (ranked[owner[c]].Entity != span.Entity)
                {
                    reasons |= ReviewReason.Overlap;
                }
            }
        }

        var result = value.ToCharArray();
        var applied = new List<(Span Span, AnonymizerAction Action)>();
        for (int start = 0; start < value.Length;)
        {
            int rank = owner[start];
            int end = start + 1;
            while (end < value.Length && owner[end] == rank)
            {
                end++;
            }
            if (rank >= 0)
            {
                var span = ranked[rank];
                var (action, own) = file.ActionFor(span.Entity);
                var fitted = FeedAnonymizer.Apply(action, span.Entity, value[start..end]);
                fitted.Text.CopyTo(0, result, start, end - start);
                reasons |= (own ? ReviewReason.None : ReviewReason.NoAction) | (fitted.Cut ? ReviewReason.Cut : ReviewReason.None)
                    | (span.Recognizer == SpacyRecognizer ? ReviewReason.SpacyGuess : ReviewReason.None);
                if (!applied.Any(a => a.Span == span))
                {
                    applied.Add((span, action));
                }
            }
            start = end;
        }
        return (new string(result), applied, reasons);
    }

    /// <summary>
    /// Sends one message's decoded strings to the embedded Presidio engine in one batch.
    /// </summary>
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
    /// Creates a value-free event.
    /// </summary>
    private static DetectionEvent Event(RecognizerFile file, int slot, FeedField field, string recognizer, string entity, double score, DetectionDecision decision,
        string op = "", ReviewReason reasons = ReviewReason.None) =>
        new(slot, field.Value.Length, Shape(field.Value), recognizer, entity, Math.Round(score, 2, MidpointRounding.AwayFromZero), decision, field.Offset, op, reasons,
            file.Threshold);

    /// <summary>
    /// Joins distinct names in ordinal order with <c>+</c>.
    /// </summary>
    private static string Names(IEnumerable<string> names) => string.Join('+', names.Where(n => n.Length > 0).Distinct().Order(StringComparer.Ordinal));

    #endregion

    #region Nested Types

    /// <summary>
    /// One span returned by Presidio.
    /// </summary>
    /// <param name="Start">The first character.</param>
    /// <param name="End">The character after the last.</param>
    /// <param name="Entity">The entity type.</param>
    /// <param name="Score">The detection score.</param>
    /// <param name="Recognizer">The recognizer name: a custom recognizer's name or a Presidio predefined recognizer.</param>
    private sealed record Span(int Start, int End, string Entity, double Score, string Recognizer);

    #endregion
}
