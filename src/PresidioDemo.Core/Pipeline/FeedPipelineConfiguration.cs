using PresidioDemo.Core.Models;
using PresidioDemo.Core.Protection;

namespace PresidioDemo.Core.Pipeline;

/// <summary>
/// The validated per-feed recognizer files that drive every feed workflow (WR-014).
/// </summary>
/// <param name="Recognizers">The recognizer file of each feed.</param>
/// <param name="PredefinedRecognizers">Whether Presidio's predefined recognizers run beside the defined ones
/// (<c>Presidio:PredefinedRecognizers</c>); on by default, the shipped setting (WR-014).</param>
public sealed record FeedPipelineConfiguration(IReadOnlyDictionary<FeedType, RecognizerFile> Recognizers, bool PredefinedRecognizers = true)
{

    #region Methods

    /// <summary>
    /// Loads and validates one recognizer XML file per feed before any input is read (WR-014).
    /// </summary>
    /// <param name="recognizerDirectory">The directory holding <c>aci.xml</c>.</param>
    /// <param name="predefinedRecognizers">Whether Presidio's predefined recognizers run too (<c>Presidio:PredefinedRecognizers</c>).</param>
    /// <returns>The validated configuration.</returns>
    /// <exception cref="InvalidDataException">A file is missing or invalid.</exception>
    public static FeedPipelineConfiguration Load(string recognizerDirectory, bool predefinedRecognizers = true) =>
        new(RecognizerFileReader.ReadAll(recognizerDirectory), predefinedRecognizers);

    /// <summary>
    /// Creates the detecting protector for these recognizer files. Call <see cref="DetectingFeedProtector.Configure"/>
    /// after <see cref="PythonHost.Start"/>.
    /// </summary>
    /// <returns>The protector, with or without Presidio's predefined recognizers as <see cref="PredefinedRecognizers"/> says.</returns>
    public DetectingFeedProtector CreateProtector() => new(Recognizers, PredefinedRecognizers);

    /// <summary>
    /// Creates the workflow registry using the given protector.
    /// </summary>
    /// <param name="protector">The local detection and protection service.</param>
    /// <returns>One workflow per supported feed.</returns>
    public FeedWorkflowRouter CreateRouter(IFeedProtector protector) => FeedWorkflowRouter.Create(protector, FeedCodecRegistry.Create);

    #endregion
}
