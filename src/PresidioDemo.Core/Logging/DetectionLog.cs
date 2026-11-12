using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using PresidioDemo.Core.Models;
using PresidioDemo.Core.Protection;

namespace PresidioDemo.Core.Logging;

#region Enumerations

/// <summary>
/// The detection log group a decoded string is listed in (WR-018).
/// </summary>
public enum DetectionGroup
{
    /// <summary>
    /// Personal data: the string was changed after a detection (masked, masked-inside).
    /// </summary>
    Pii,
    /// <summary>
    /// Not personal data: the string was published unchanged (kept, anchor).
    /// </summary>
    NonPii,
    /// <summary>
    /// Worth a recognizer change: masked with no format or keep (masked-by-default), or kept with a weak detection inside
    /// (missed-below-threshold).
    /// </summary>
    Review
}

#endregion

/// <summary>
/// Formats the detection log (WR-018): one block per message, with a header line and the decoded strings listed in the
/// PII, non-PII and review groups, each exactly once. A string is located by its slot and payload byte offset.
/// Value-free unless decoded values are passed, which happens only with
/// <c>Presidio:DetectionLogValues</c> on in a non-production environment (WR-020). Written only while
/// <c>Presidio:DetectionLog</c> is on.
/// </summary>
/// <remarks>
/// The header starts in the first column and every other line is indented, so a log collector can treat each block as one
/// entry (a multiline start pattern of <c>^\S</c>). Values and reasons are JSON-encoded, so neither can break a line or
/// start a forged entry.
/// </remarks>
public static class DetectionLog
{

    #region Fields and Constants

    /// <summary>
    /// The indent of an entry line.
    /// </summary>
    private const string EntryIndent = "    ";

    /// <summary>
    /// The indent of a group heading.
    /// </summary>
    private const string GroupIndent = "  ";

    /// <summary>
    /// Encodes values readably (an apostrophe stays an apostrophe) while still escaping quotes, backslashes and control
    /// characters, so an encoded value always stays on one line.
    /// </summary>
    private static readonly JsonSerializerOptions ValueEncoding = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    #endregion

    #region Methods

    /// <summary>
    /// Returns the log word for a decision.
    /// </summary>
    /// <param name="decision">The decision.</param>
    /// <returns>A lower-case, hyphenated word.</returns>
    public static string Decision(DetectionDecision decision) => decision switch
    {
        DetectionDecision.Masked => "masked",
        DetectionDecision.Kept => "kept",
        DetectionDecision.MaskedInside => "masked-inside",
        DetectionDecision.Anchor => "anchor",
        DetectionDecision.MaskedByDefault => "masked-by-default",
        DetectionDecision.MissedBelowThreshold => "missed-below-threshold",
        _ => throw new ArgumentOutOfRangeException(nameof(decision))
    };

    /// <summary>
    /// Encodes a value or reason as one JSON string. Beyond JSON's own escapes, the relaxed encoder
    /// already escapes line and paragraph separators; zero-width and bidirectional formatting characters are escaped too, so
    /// a value can neither break its line nor change how the rest of the line displays.
    /// </summary>
    /// <param name="value">The text.</param>
    /// <returns>The quoted, escaped text, which decodes back to <paramref name="value"/>.</returns>
    public static string Encode(string value)
    {
        string encoded = JsonSerializer.Serialize(value, ValueEncoding);
        if (!encoded.Any(IsFormatting))
        {
            return encoded;
        }
        var escaped = new StringBuilder(encoded.Length + 16);
        foreach (char c in encoded)
        {
            escaped.Append(IsFormatting(c) ? string.Create(CultureInfo.InvariantCulture, $"\\u{(int)c:X4}") : c.ToString());
        }
        return escaped.ToString();
    }

    /// <summary>
    /// Returns the detection log block for one message.
    /// </summary>
    /// <param name="feed">The feed route.</param>
    /// <param name="transaction">The transaction identifier.</param>
    /// <param name="events">The events from the protector, one per decoded string.</param>
    /// <param name="rejectReason">The value-free dead-letter reason, or null for a published message.</param>
    /// <param name="before">The decoded values by slot, or null for a value-free block (WR-020).</param>
    /// <param name="after">The published values by slot, or null; ignored for a value-free block.</param>
    /// <returns>The block, its lines separated by <see cref="Environment.NewLine"/> and ending with one.</returns>
    public static string FormatBlock(FeedType feed, Guid transaction, IReadOnlyList<DetectionEvent> events, string? rejectReason = null,
        IReadOnlyList<string>? before = null, IReadOnlyList<string>? after = null)
    {
        var groups = Enumerable.Range(0, events.Count).ToLookup(i => Group(events[i].Decision));
        var locations = events.Select(Location).ToArray();
        int width = locations.Select(location => location.Length).DefaultIfEmpty(0).Max();

        var block = new StringBuilder();
        block.Append(CultureInfo.InvariantCulture,
            $"{FeedCatalog.Get(feed).FolderName} {transaction:N} DETECTION {(rejectReason is null ? "PUBLISHED" : "DEAD-LETTERED")} strings={events.Count} pii={groups[DetectionGroup.Pii].Count()} non-pii={groups[DetectionGroup.NonPii].Count()} review={groups[DetectionGroup.Review].Count()}");
        block.Append(" offsets=payload");
        if (rejectReason is not null)
        {
            block.Append(" reason=").Append(Encode(rejectReason));
        }
        block.Append(Environment.NewLine);

        foreach (var (group, heading) in new[]
        {
            (DetectionGroup.Pii, "PII fields (changed)"),
            (DetectionGroup.NonPii, "Non-PII fields (unchanged)"),
            (DetectionGroup.Review, "Review (a format or keep may be needed)")
        })
        {
            block.Append(GroupIndent).Append(heading).Append(Environment.NewLine);
            if (!groups[group].Any())
            {
                // An empty group is printed, so a reader knows it was checked rather than left out.
                block.Append(EntryIndent).Append("(none)").Append(Environment.NewLine);
            }
            foreach (int index in groups[group])
            {
                var e = events[index];
                block.Append(EntryIndent).Append(locations[index].PadRight(width)).Append("  ")
                    .Append(Value(e, group, rejectReason is not null, before, after)).Append("  ")
                    .Append(CultureInfo.InvariantCulture, $"format={e.Format} entity={(e.Entity.Length == 0 ? "-" : e.Entity)} score={e.Score:0.00} decision={Decision(e.Decision)}")
                    .Append(Environment.NewLine);
            }
        }
        return block.ToString();
    }

    /// <summary>
    /// Returns the group a decision is listed in (WR-018).
    /// </summary>
    /// <param name="decision">The decision.</param>
    /// <returns>The group.</returns>
    public static DetectionGroup Group(DetectionDecision decision) => decision switch
    {
        DetectionDecision.Masked or DetectionDecision.MaskedInside => DetectionGroup.Pii,
        DetectionDecision.Kept or DetectionDecision.Anchor => DetectionGroup.NonPii,
        DetectionDecision.MaskedByDefault or DetectionDecision.MissedBelowThreshold => DetectionGroup.Review,
        _ => throw new ArgumentOutOfRangeException(nameof(decision))
    };

    /// <summary>
    /// Returns whether a decision changes the string.
    /// </summary>
    /// <param name="decision">The decision.</param>
    /// <returns>True for the PII decisions and masked-by-default.</returns>
    private static bool Changes(DetectionDecision decision) => Group(decision) == DetectionGroup.Pii || decision == DetectionDecision.MaskedByDefault;

    /// <summary>
    /// Returns whether a character is a zero-width or bidirectional formatting character (U+200B to U+200F, U+202A to
    /// U+202E, U+2066 to U+2069), which would display invisibly or reorder the text after it.
    /// </summary>
    /// <param name="c">The character.</param>
    /// <returns>True for those characters.</returns>
    private static bool IsFormatting(char c) => c is >= (char)0x200B and <= (char)0x200F or >= (char)0x202A and <= (char)0x202E or >= (char)0x2066 and <= (char)0x2069;

    /// <summary>
    /// Returns where a string sits: <c>slot 12 @0x01A4</c>, or <c>slot 12</c> when the codec reported no offset.
    /// </summary>
    /// <param name="e">The event.</param>
    /// <returns>The location text.</returns>
    private static string Location(DetectionEvent e) => e.Offset is int offset
        ? string.Create(CultureInfo.InvariantCulture, $"slot {e.Slot} @0x{offset:X4}")
        : string.Create(CultureInfo.InvariantCulture, $"slot {e.Slot}");

    /// <summary>
    /// Returns an entry's value part: <c>"before" -> "after"</c> or <c>"before"</c> under WR-020, otherwise
    /// <c>len=</c> and <c>shape=</c>. A review entry says whether the string changed.
    /// </summary>
    /// <param name="e">The event.</param>
    /// <param name="group">Its group.</param>
    /// <param name="rejected">Whether the message was dead-lettered.</param>
    /// <param name="before">The decoded values by slot, or null.</param>
    /// <param name="after">The published values by slot, or null.</param>
    /// <returns>The value part.</returns>
    private static string Value(DetectionEvent e, DetectionGroup group, bool rejected, IReadOnlyList<string>? before, IReadOnlyList<string>? after)
    {
        bool changes = Changes(e.Decision);
        string text;
        // A slot without a value (a protector that supplied fewer values) keeps the value-free form instead of failing.
        if (before is not null && e.Slot >= 0 && e.Slot < before.Count)
        {
            text = Encode(before[e.Slot]);
            if (changes)
            {
                text += rejected || after is null || e.Slot >= after.Count ? " -> not published" : " -> " + Encode(after[e.Slot]);
            }
        }
        else
        {
            text = string.Create(CultureInfo.InvariantCulture, $"len={e.Length} shape={e.Shape}");
        }
        return group == DetectionGroup.Review ? text + (changes ? "  changed" : "  unchanged") : text;
    }

    #endregion
}
