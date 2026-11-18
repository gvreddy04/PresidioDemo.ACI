using PresidioDemo.Core.Models;

namespace PresidioDemo.Core.Decoder;

/// <summary>
/// Decodes, rebuilds and validates ACI messages; the shared logic is in <see cref="XdrFeedDecoder"/>.
/// </summary>
public sealed class AciDecoder() : XdrFeedDecoder(FeedType.ACI)
{
}
