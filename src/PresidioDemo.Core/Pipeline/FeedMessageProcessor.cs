using PresidioDemo.Core.Models;
using PresidioDemo.Core.Protection;

namespace PresidioDemo.Core.Pipeline;

#region Models

/// <summary>
/// The outcome of processing one message: validated protected content, or the reason it was rejected.
/// </summary>
/// <param name="Message">The original input delivery and bytes.</param>
/// <param name="Workflow">The validated output and diagnostic field sets, or null when rejected.</param>
/// <param name="Reason">The rejection reason, or null when published.</param>
/// <param name="RejectedEvents">For a message rejected after detection ran, its value-free detection events; otherwise null.</param>
/// <param name="RejectedValues">For a message rejected after detection ran, its decoded candidate values; otherwise null.</param>
public sealed record FeedProcessingResult(FeedMessage Message, FeedWorkflowResult? Workflow, string? Reason,
    IReadOnlyList<DetectionEvent>? RejectedEvents = null, IReadOnlyList<string>? RejectedValues = null)
{

    #region Properties, Indexers

    /// <summary>
    /// Gets the decoded candidate values for the detection log (WR-020): from the published output, or from a rejection
    /// raised after detection; null when detection did not run.
    /// </summary>
    /// <value>The values by event slot, or null.</value>
    public IReadOnlyList<string>? DetectionValues => Workflow?.CandidateValues ?? RejectedValues;

    /// <summary>
    /// Gets the value-free detection events for the detection log: from the published output, or from a rejection raised
    /// after detection; null when detection did not run.
    /// </summary>
    /// <value>The events, or null.</value>
    public IReadOnlyList<DetectionEvent>? DetectionEvents => Workflow?.Events ?? RejectedEvents;

    /// <summary>
    /// Gets a value indicating whether the message produced validated protected output.
    /// </summary>
    /// <value>Whether the output can be published.</value>
    public bool Published => Workflow is not null;

    #endregion
}

#endregion

/// <summary>
/// Runs the feed's workflow for one message without any transport concerns.
/// </summary>
/// <param name="router">The registry resolving a workflow for each supported feed route.</param>
public sealed class FeedMessageProcessor(FeedWorkflowRouter router)
{

    #region Methods

    /// <summary>
    /// Parses, protects, reconstructs and validates one complete message.
    /// </summary>
    /// <param name="feed">The supported feed route.</param>
    /// <param name="messageId">The stable transaction ID.</param>
    /// <param name="name">The message name; a .txt extension selects an IBM MQ export, .bin a raw payload.</param>
    /// <param name="content">The complete input bytes.</param>
    /// <param name="cancellationToken">The token used to stop processing during shutdown.</param>
    /// <returns>The validated output, or the reason the message was rejected.</returns>
    public async Task<FeedProcessingResult> ProcessAsync(FeedType feed, Guid messageId, string name, ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken)
    {
        var message = new FeedMessage(new FeedDelivery(feed, messageId, name, ""), content);
        try
        {
            return new(message, await router.Get(feed).ProcessAsync(message, cancellationToken), null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Codec and policy contracts explain themselves; anything else is reported without internal detail. A rejection
            // after detection keeps its events and values for the detection log (WR-020).
            var trace = DetectionTrace.From(ex);
            return new(message, null, ex is InvalidDataException ? ex.Message : "Feed processing failed.", trace?.Events, trace?.CandidateValues);
        }
    }

    #endregion
}
