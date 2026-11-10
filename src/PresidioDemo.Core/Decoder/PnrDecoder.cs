using PresidioDemo.Core.Models;

namespace PresidioDemo.Core.Decoder;

/// <summary>
/// Decodes, rebuilds and validates PNR messages; the shared logic is in <see cref="XdrFeedDecoder"/>.
/// </summary>
public sealed class PnrDecoder() : XdrFeedDecoder(FeedType.PNR)
{
}
