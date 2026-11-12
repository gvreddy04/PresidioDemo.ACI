using PresidioDemo.Core.Decoder;
using PresidioDemo.Core.Models;

namespace PresidioDemo.Core.Pipeline;

/// <summary>
/// Selects the decoded-text codec for a delivery route: the generic XDR codec for binary feeds (no per-feed schema),
/// the shared JSON codec for JSON feeds.
/// </summary>
public static class FeedCodecRegistry
{

    #region Methods

    /// <summary>
    /// Returns the codec for a feed route.
    /// </summary>
    /// <param name="feed">The supported feed route.</param>
    /// <returns>The codec.</returns>
    public static IFeedCodec Create(FeedType feed) => feed switch
    {
        FeedType.PNR => new PnrDecoder(),
        _ => throw new InvalidDataException("No codec is registered for this feed.")
    };

    #endregion
}
