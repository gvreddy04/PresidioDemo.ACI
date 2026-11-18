using PresidioDemo.Core.Models;

namespace PresidioDemo.Core.Logging;

/// <summary>
/// Formats transaction logs for the ACI feed.
/// </summary>
public sealed class AciFeedLogger : FeedLogger
{

    #region Properties, Indexers

    /// <inheritdoc />
    public override FeedType Feed => FeedType.ACI;

    #endregion
}
