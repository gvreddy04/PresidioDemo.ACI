using System.Diagnostics;
using PresidioDemo.Core.Models;
using PresidioDemo.Core.Protection;

namespace PresidioDemo.Core.Pipeline;

/// <summary>
/// Coordinates decoding, detection and protection, reconstruction and validation for one feed.
/// </summary>
/// <param name="protector">The local detection and protection service.</param>
/// <param name="codec">The decoder, serializer and validator selected for this feed.</param>
public abstract class ProtectedFeedWorkflow(IFeedProtector protector, IFeedCodec codec) : IFeedWorkflow
{

    #region Methods

    /// <summary>
    /// Decodes, protects, reconstructs and validates one complete delivery before a durable outcome.
    /// </summary>
    /// <param name="message">The complete input delivery and its retained message bytes.</param>
    /// <param name="cancellationToken">The token used to interrupt processing while retaining recoverable input.</param>
    /// <returns>A task containing the validated protected output, its diagnostic field sets and detection events.</returns>
    /// <exception cref="InvalidDataException">A structural failure (WR-016); the message is dead-lettered.</exception>
    public async ValueTask<FeedWorkflowResult> ProcessAsync(FeedMessage message, CancellationToken cancellationToken)
    {
        if (message.Delivery.Feed != Feed)
        {
            throw new InvalidDataException("Feed strategy and delivery do not match.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var timer = Stopwatch.StartNew();
        var parsed = codec.Parse(message);
        Console.WriteLine($"{FeedCatalog.Get(Feed).FolderName,-12} DECODED    {parsed.Fields.Count} fields | {timer.ElapsedMilliseconds} ms");
        timer.Restart();
        var outcome = await protector.ProtectAsync(Feed, parsed, cancellationToken);
        Console.WriteLine($"{FeedCatalog.Get(Feed).FolderName,-12} DETECTED   {outcome.Events.Count} strings | {timer.ElapsedMilliseconds} ms (includes engine wait)");
        cancellationToken.ThrowIfCancellationRequested();
        timer.Restart();
        byte[] content;
        try
        {
            content = codec.Serialize(parsed, outcome.Values);
            codec.Validate(parsed, content);
        }
        catch (InvalidDataException ex) when (DetectionTrace.From(ex) is null)
        {
            // Detection already ran, so the dead-lettered message keeps its events for the detection log (WR-020).
            throw new DetectionTrace(outcome.Events, outcome.CandidateValues ?? []).Reject(ex.Message, ex);
        }
        Console.WriteLine($"{FeedCatalog.Get(Feed).FolderName,-12} SERIALIZED Original format rebuilt and validated | {timer.ElapsedMilliseconds} ms");
        cancellationToken.ThrowIfCancellationRequested();
        var loggedFields = parsed.Fields.Select(field => field with { Value = outcome.Values[field.Id] }).ToArray();
        return new FeedWorkflowResult(content, parsed.Fields, loggedFields, outcome.Events, outcome.CandidateValues);
    }

    #endregion

    #region Properties, Indexers

    /// <summary>
    /// Gets the feed route handled by this workflow.
    /// </summary>
    /// <value>The feed route handled by this workflow.</value>
    public abstract FeedType Feed { get; }

    #endregion
}
