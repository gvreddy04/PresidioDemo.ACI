using PresidioDemo.Core.Models;

namespace PresidioDemo.Core.Logging;

/// <summary>
/// Formats transaction logs for the PNR feed.
/// </summary>
public sealed class PnrFeedLogger : FeedLogger
{

    #region Properties, Indexers

    /// <inheritdoc />
    public override FeedType Feed => FeedType.PNR;

    #endregion
}
