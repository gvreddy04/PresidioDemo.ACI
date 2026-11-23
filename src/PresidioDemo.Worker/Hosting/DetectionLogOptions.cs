namespace PresidioDemo.Worker.Hosting;

/// <summary>
/// The detection log settings, bound from <c>Presidio:DetectionLog</c>. Both are read at startup, are on by default and
/// are the same in every environment; a deployment switches one off with its environment variable, and the DevOps team
/// decides this for production (WR-018, WR-020).
/// </summary>
public sealed class DetectionLogOptions
{

    #region Properties, Indexers

    /// <summary>
    /// Gets or sets whether the detection log is written: one block per message whose strings were detected (WR-018). On
    /// by default; <c>Presidio__DetectionLog__Enabled=false</c> switches it off.
    /// </summary>
    /// <value>True to write the detection blocks.</value>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Gets or sets whether every detection log line, PII, non-PII and review alike, also carries the JSON-encoded before
    /// and after values (WR-020). On by default, and in effect only while <see cref="Enabled"/> is on;
    /// <c>Presidio__DetectionLog__IncludePiiValues=false</c> keeps the lines value-free.
    /// </summary>
    /// <value>True to append the decoded values to each detection log line.</value>
    public bool IncludePiiValues { get; set; } = true;

    #endregion
}
