namespace PresidioDemo.Protection;

/// <summary>
/// The value-free detection events and decoded candidate values of a message rejected after detection ran (WR-016),
/// attached to its <see cref="InvalidDataException"/> so the detection log can still describe it (WR-020). The exception
/// message stays the reviewed, value-free reason (CS-007).
/// </summary>
/// <param name="Events">The detection events, in candidate order.</param>
/// <param name="CandidateValues">The decoded value of each candidate, by slot; logged only with
/// <c>Presidio:DetectionLogValues</c> on.</param>
public sealed record DetectionTrace(IReadOnlyList<DetectionEvent> Events, IReadOnlyList<string> CandidateValues)
{

    #region Fields and Constants

    /// <summary>
    /// The <see cref="Exception.Data"/> key the trace is stored under.
    /// </summary>
    private const string DataKey = "PresidioDemo.DetectionTrace";

    #endregion

    #region Methods

    /// <summary>
    /// Returns the trace attached to a rejection, or null when the rejection happened before detection.
    /// </summary>
    /// <param name="exception">The rejection.</param>
    /// <returns>The trace, or null.</returns>
    public static DetectionTrace? From(Exception exception) => exception.Data[DataKey] as DetectionTrace;

    /// <summary>
    /// Creates a rejection that carries this trace.
    /// </summary>
    /// <param name="message">The reviewed, value-free rejection reason.</param>
    /// <param name="innerException">The rejection raised by rebuild or validation, if any.</param>
    /// <returns>The exception to throw.</returns>
    public InvalidDataException Reject(string message, Exception? innerException = null)
    {
        var rejection = new InvalidDataException(message, innerException);
        rejection.Data[DataKey] = this;
        return rejection;
    }

    #endregion
}
