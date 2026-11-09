using System.Globalization;
using System.Text.Json;
using PresidioDemo.Feeds.Shared;
using PresidioDemo.Protection;

namespace PresidioDemo.Transport;

/// <summary>
/// Formats the detection log (WR-018): one line per decoded string with its slot, length, character shape, matched
/// format or <c>none</c>, entity, score and decision. Value-free unless decoded values are passed, which happens only with
/// <c>Presidio:DetectionLogValues</c> on in a non-production environment (WR-020). Written only while
/// <c>Presidio:DetectionLog</c> is on.
/// </summary>
public static class DetectionLog
{

    #region Methods

    /// <summary>
    /// Returns one log line per detection event.
    /// </summary>
    /// <param name="feed">The feed route.</param>
    /// <param name="transaction">The transaction identifier.</param>
    /// <param name="events">The events from the protector.</param>
    /// <param name="values">The decoded candidate values by slot, or null for value-free lines. When given, each line ends
    /// with <c>value=</c> and the JSON-encoded value, so a value cannot break the line or forge another (WR-020).</param>
    /// <returns>The lines, in candidate order.</returns>
    public static IReadOnlyList<string> Format(FeedType feed, Guid transaction, IReadOnlyList<DetectionEvent> events,
        IReadOnlyList<string>? values = null)
    {
        string folder = FeedCatalog.Get(feed).FolderName;
        return events.Select(e =>
        {
            string line = string.Create(CultureInfo.InvariantCulture,
                $"{folder} {transaction:N} DETECT slot={e.Slot} key={(e.Key.Length == 0 ? "-" : e.Key)} len={e.Length} shape={e.Shape} format={e.Format} entity={(e.Entity.Length == 0 ? "-" : e.Entity)} score={e.Score:0.00} decision={Decision(e.Decision)}");
            return values is null ? line : line + " value=" + JsonSerializer.Serialize(values[e.Slot]);
        }).ToArray();
    }

    /// <summary>
    /// Returns the log word for a decision.
    /// </summary>
    /// <param name="decision">The decision.</param>
    /// <returns>A lower-case, hyphenated word.</returns>
    public static string Decision(DetectionDecision decision) => decision switch
    {
        DetectionDecision.Masked => "masked",
        DetectionDecision.Replaced => "replaced",
        DetectionDecision.Kept => "kept",
        DetectionDecision.MaskedInside => "masked-inside",
        DetectionDecision.Anchor => "anchor",
        DetectionDecision.MaskedByDefault => "masked-by-default",
        DetectionDecision.MissedBelowThreshold => "missed-below-threshold",
        _ => throw new ArgumentOutOfRangeException(nameof(decision))
    };

    #endregion
}
