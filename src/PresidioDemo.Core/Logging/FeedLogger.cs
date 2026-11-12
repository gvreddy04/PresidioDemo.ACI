using PresidioDemo.Core.Models;

namespace PresidioDemo.Core.Logging;

/// <summary>
/// Formats transaction evidence for one feed. The feed guard and the call to <see cref="FeedTransactionLog"/> live here
/// once; each feed has one sealed child that only names its feed.
/// </summary>
public abstract class FeedLogger
{

    #region Properties, Indexers

    /// <summary>
    /// Gets the feed route handled by this logger.
    /// </summary>
    /// <value>The feed.</value>
    public abstract FeedType Feed { get; }

    #endregion

    #region Methods

    /// <summary>
    /// Formats a transaction using its original and protected message data.
    /// </summary>
    /// <param name="message">The original delivery.</param>
    /// <param name="result">The validated output and diagnostic fields, or null when rejected.</param>
    /// <param name="reason">The rejection reason, or null when published.</param>
    /// <param name="detection">The detection log block for this message, or null when detection did not run.</param>
    /// <returns>The transaction log text.</returns>
    /// <exception cref="InvalidDataException">The delivery belongs to another feed.</exception>
    public string Format(FeedMessage message, FeedWorkflowResult? result, string? reason, string? detection = null)
    {
        if (message.Delivery.Feed != Feed)
        {
            throw new InvalidDataException("Feed logger and delivery route differ.");
        }
        return FeedTransactionLog.Format(message, result, reason, detection);
    }

    #endregion
}
