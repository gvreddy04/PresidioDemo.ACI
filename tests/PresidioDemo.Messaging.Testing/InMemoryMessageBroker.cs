using System.Runtime.CompilerServices;
using System.Threading.Channels;
using PresidioDemo.Messaging.Abstractions;
using PresidioDemo.Messaging.Models;

namespace PresidioDemo.Messaging.Testing;

/// <summary>
/// A test-only broker with durable-queue semantics: one in-flight message per reader, redelivery of
/// uncompleted messages with a higher delivery count, topic-to-queue subscriptions, live topic subscribers and confirmed publishing.
/// </summary>
public sealed class InMemoryMessageBroker : IMessagingConnection, IMessageConsumer, IMessagePublisher, IMessageSubscriber
{

    #region Fields and Constants

    /// <summary>
    /// Guards every queue, subscription and publication list.
    /// </summary>
    private readonly Lock _gate = new();

    /// <summary>
    /// Every confirmed publication in order.
    /// </summary>
    private readonly List<OutboundMessage> _published = [];

    /// <summary>
    /// The stored messages of each queue in arrival order.
    /// </summary>
    private readonly Dictionary<string, List<Stored>> _queues = new(StringComparer.Ordinal);

    /// <summary>
    /// The queues attracting each topic.
    /// </summary>
    private readonly Dictionary<string, List<string>> _subscriptions = new(StringComparer.Ordinal);

    /// <summary>
    /// The live subscribers of each topic, each receiving a copy of every later publication.
    /// </summary>
    private readonly Dictionary<string, List<Channel<InboundMessage>>> _subscribers = new(StringComparer.Ordinal);

    /// <summary>
    /// Completes whenever a queue changes, waking waiting readers.
    /// </summary>
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// The next stable message ID.
    /// </summary>
    private int _nextId;

    #endregion

    #region Methods

    /// <summary>
    /// Does nothing; the in-memory broker is always connected.
    /// </summary>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>A completed task.</returns>
    public Task ConnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Does nothing; there is no connection to release.
    /// </summary>
    /// <returns>A completed task.</returns>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    /// <summary>
    /// Returns how many messages, including in-flight ones, wait on a queue.
    /// </summary>
    /// <param name="queue">The queue name.</param>
    /// <returns>The stored message count.</returns>
    public int Pending(string queue)
    {
        lock (_gate)
        {
            return _queues.TryGetValue(queue, out var stored) ? stored.Count : 0;
        }
    }

    /// <summary>
    /// Records a confirmed publication and routes it to the queue, or to every queue subscribed to the topic.
    /// </summary>
    /// <param name="message">The message and its destination.</param>
    /// <param name="cancellationToken">Unused.</param>
    /// <returns>A completed task.</returns>
    /// <exception cref="MessagingUnavailableException">A simulated outage was requested with <see cref="FailNextPublishes"/>.</exception>
    public Task PublishAsync(OutboundMessage message, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            PublishAttempts++;
            if (FailNextPublishes > 0)
            {
                FailNextPublishes--;
                throw new MessagingUnavailableException("Simulated broker outage.");
            }
            _published.Add(message);
            List<string> targets = message.Destination.Kind == DestinationKind.Queue ? [message.Destination.Name]
                : _subscriptions.GetValueOrDefault(message.Destination.Name) ?? [];
            foreach (string queue in targets)
            {
                Enqueue(queue, new(NextId(), message.Payload.ToArray(), message.CorrelationId, new(message.Headers)));
            }
            if (message.Destination.Kind == DestinationKind.Topic && _subscribers.TryGetValue(message.Destination.Name, out var live))
            {
                foreach (var subscriber in live)
                {
                    subscriber.Writer.TryWrite(new(message.Destination.Name, NextId(), message.Payload.ToArray(), message.CorrelationId,
                        new Dictionary<string, string>(message.Headers, StringComparer.Ordinal), 1, _ => ValueTask.CompletedTask));
                }
            }
            Pulse();
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Returns the confirmed publications to one destination name.
    /// </summary>
    /// <param name="destination">The topic or queue name.</param>
    /// <returns>The publications in order.</returns>
    public IReadOnlyList<OutboundMessage> PublishedTo(string destination)
    {
        lock (_gate)
        {
            return _published.Where(m => m.Destination.Name == destination).ToArray();
        }
    }

    /// <summary>
    /// Streams a queue's messages one at a time; a message not completed before the next read, or when reading stops, is redelivered.
    /// </summary>
    /// <param name="source">The queue name.</param>
    /// <param name="cancellationToken">The token that stops reading.</param>
    /// <returns>The received messages in queue order.</returns>
    public async IAsyncEnumerable<InboundMessage> ReadAsync(string source, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        while (true)
        {
            Stored? next;
            Task changed;
            lock (_gate)
            {
                changed = _changed.Task;
                next = _queues.GetValueOrDefault(source)?.FirstOrDefault(m => !m.InFlight);
                if (next is not null)
                {
                    next.InFlight = true;
                    next.Deliveries++;
                }
            }
            if (next is null)
            {
                await changed.WaitAsync(cancellationToken);
                continue;
            }

            bool completed = false;
            try
            {
                yield return new(source, next.Id, next.Payload, next.CorrelationId, next.Headers, next.Deliveries, _ =>
                {
                    lock (_gate)
                    {
                        _queues[source].Remove(next);
                        completed = true;
                        Pulse();
                    }
                    return ValueTask.CompletedTask;
                });
            }
            finally
            {
                if (!completed)
                {
                    // Not acknowledged: the broker keeps it and delivers it again.
                    lock (_gate)
                    {
                        next.InFlight = false;
                        Pulse();
                    }
                }
            }
        }
    }

    /// <summary>
    /// Places a producer message on a queue.
    /// </summary>
    /// <param name="queue">The queue name.</param>
    /// <param name="payload">The message body.</param>
    /// <param name="headers">Optional string headers.</param>
    /// <param name="correlationId">Optional correlation ID.</param>
    /// <returns>The message's stable ID.</returns>
    public string Send(string queue, ReadOnlyMemory<byte> payload, IReadOnlyDictionary<string, string>? headers = null, string? correlationId = null)
    {
        lock (_gate)
        {
            var stored = new Stored(NextId(), payload.ToArray(), correlationId, new(headers ?? new Dictionary<string, string>(), StringComparer.Ordinal));
            Enqueue(queue, stored);
            Pulse();
            return stored.Id;
        }
    }

    /// <summary>
    /// Makes a queue attract every message published to a topic, as a broker queue subscription does.
    /// </summary>
    /// <param name="queue">The queue name.</param>
    /// <param name="topic">The topic name.</param>
    public void Subscribe(string queue, string topic)
    {
        lock (_gate)
        {
            if (!_subscriptions.TryGetValue(topic, out var queues))
            {
                _subscriptions[topic] = queues = [];
            }
            queues.Add(queue);
        }
    }

    /// <summary>
    /// Streams a copy of every message published to a topic from the first read until cancellation, as a live subscriber.
    /// </summary>
    /// <param name="topic">The topic name, matched exactly.</param>
    /// <param name="cancellationToken">The token that stops receiving.</param>
    /// <returns>The received messages in publish order; completing one does nothing.</returns>
    public async IAsyncEnumerable<InboundMessage> SubscribeAsync(string topic, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var channel = Channel.CreateUnbounded<InboundMessage>(new UnboundedChannelOptions { SingleReader = true });
        lock (_gate)
        {
            if (!_subscribers.TryGetValue(topic, out var live))
            {
                _subscribers[topic] = live = [];
            }
            live.Add(channel);
        }
        try
        {
            await foreach (var message in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yield return message;
            }
        }
        finally
        {
            lock (_gate)
            {
                _subscribers[topic].Remove(channel);
            }
        }
    }

    /// <summary>
    /// Waits until every listed queue is empty.
    /// </summary>
    /// <param name="queues">The queue names.</param>
    /// <param name="timeout">The longest wait.</param>
    /// <returns>A task that completes when the queues are drained.</returns>
    /// <exception cref="TimeoutException">A queue still holds messages after the timeout.</exception>
    public async Task WaitUntilDrainedAsync(IEnumerable<string> queues, TimeSpan timeout)
    {
        var names = queues.ToArray();
        using var limit = new CancellationTokenSource(timeout);
        while (true)
        {
            Task changed;
            lock (_gate)
            {
                changed = _changed.Task;
                if (names.All(q => !_queues.TryGetValue(q, out var stored) || stored.Count == 0))
                {
                    return;
                }
            }
            try { await changed.WaitAsync(limit.Token); }
            catch (OperationCanceledException) { throw new TimeoutException("In-memory queues were not drained in time."); }
        }
    }

    /// <summary>
    /// Adds a message to a queue, creating the queue on first use.
    /// </summary>
    /// <param name="queue">The queue name.</param>
    /// <param name="stored">The message.</param>
    private void Enqueue(string queue, Stored stored)
    {
        if (!_queues.TryGetValue(queue, out var list))
        {
            _queues[queue] = list = [];
        }
        list.Add(stored);
    }

    /// <summary>
    /// Returns the next stable message ID.
    /// </summary>
    /// <returns>An ID such as mem-7.</returns>
    private string NextId() => "mem-" + Interlocked.Increment(ref _nextId);

    /// <summary>
    /// Wakes every waiting reader; call while holding the gate.
    /// </summary>
    private void Pulse()
    {
        var previous = _changed;
        _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        previous.TrySetResult();
    }

    #endregion

    #region Properties, Indexers

    /// <summary>
    /// Gets or sets how many upcoming publishes fail as a simulated outage.
    /// </summary>
    /// <value>The number of publishes to fail.</value>
    public int FailNextPublishes { get; set; }

    /// <summary>
    /// Gets how many publishes were attempted, including simulated failures.
    /// </summary>
    /// <value>The attempt count.</value>
    public int PublishAttempts { get; private set; }

    /// <summary>
    /// Gets the transport name shown in logs.
    /// </summary>
    /// <value>InMemory.</value>
    public string Transport => "InMemory";

    #endregion

    #region Nested Types

    /// <summary>
    /// A stored queue message and its delivery state.
    /// </summary>
    /// <param name="Id">The stable message ID.</param>
    /// <param name="Payload">The message body.</param>
    /// <param name="CorrelationId">The correlation ID, or null.</param>
    /// <param name="Headers">The string headers.</param>
    private sealed record Stored(string Id, byte[] Payload, string? CorrelationId, Dictionary<string, string> Headers)
    {
        public int Deliveries { get; set; }
        public bool InFlight { get; set; }
    }

    #endregion
}
