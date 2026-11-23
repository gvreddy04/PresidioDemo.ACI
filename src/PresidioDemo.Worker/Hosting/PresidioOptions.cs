using Microsoft.Extensions.Configuration;

namespace PresidioDemo.Worker.Hosting;

/// <summary>
/// The protection and detection log settings, bound from the Presidio section; relative paths resolve against the
/// application folder. Every setting is the same in every environment; a deployment changes one with its
/// <c>Presidio__</c> environment variable (WR-018, WR-020).
/// </summary>
public sealed class PresidioOptions
{

    #region Fields and Constants

    /// <summary>
    /// The retired keys and the keys that replace them. A retired key stops startup, so a deployment that still sets one,
    /// such as <c>Presidio__DetectionLogValues=false</c>, cannot lose its setting silently.
    /// </summary>
    private static readonly (string Retired, string Replacement)[] RetiredKeys =
    [
        ("DefaultDetection", "Presidio:PredefinedRecognizers"),
        ("DetectionLogValues", "Presidio:DetectionLog:IncludePiiValues"),
        ("DetectionLog", "Presidio:DetectionLog:Enabled")
    ];

    #endregion

    #region Properties, Indexers

    /// <summary>
    /// Gets or sets the detection log settings (WR-018, WR-020).
    /// </summary>
    /// <value>Whether blocks are written and whether they carry values; both on by default.</value>
    public DetectionLogOptions DetectionLog { get; set; } = new();

    /// <summary>
    /// Gets or sets whether Presidio's predefined recognizers (email, phone, credit card, IP address, URL, the spaCy
    /// PERSON, LOCATION, NRP and DATE_TIME guesses and the rest) run beside the recognizers defined in each feed's
    /// recognizer file (WR-014). On by default; <c>Presidio__PredefinedRecognizers=false</c> leaves only the defined
    /// recognizers. Read at startup.
    /// </summary>
    /// <value>True to run the predefined recognizers too, except those the file switches off.</value>
    public bool PredefinedRecognizers { get; set; } = true;

    /// <summary>
    /// Gets or sets the Python virtual environment folder, or null for the project's src/.venv.
    /// </summary>
    /// <value>The folder that holds pyvenv.cfg, such as /opt/venv in the container image.</value>
    public string? PythonEnvironment { get; set; }

    /// <summary>
    /// Gets or sets the folder that holds one recognizer XML file per feed (WR-014). The files ship inside the image
    /// (PR-005); the folder is resolved against the application folder.
    /// </summary>
    /// <value>The folder path, by default <c>Configuration/recognizers</c>.</value>
    public string RecognizerDirectory { get; set; } = "Configuration/recognizers";

    /// <summary>
    /// Gets whether detection log lines carry decoded values: both <see cref="DetectionLogOptions.Enabled"/> and
    /// <see cref="DetectionLogOptions.IncludePiiValues"/> are on (WR-020).
    /// </summary>
    /// <value>True when values are appended to detection log lines.</value>
    public bool WritesValues => DetectionLog.Enabled && DetectionLog.IncludePiiValues;

    #endregion

    #region Methods

    /// <summary>
    /// Binds the Presidio section strictly and resolves the file paths.
    /// </summary>
    /// <param name="configuration">The environment-resolved configuration.</param>
    /// <param name="baseDirectory">The folder that relative paths resolve against.</param>
    /// <returns>The options with absolute paths.</returns>
    /// <exception cref="InvalidOperationException">A retired key is set, or the configured Python environment has no
    /// pyvenv.cfg.</exception>
    public static PresidioOptions Load(IConfiguration configuration, string baseDirectory)
    {
        var section = configuration.GetSection("Presidio");
        RejectRetiredKeys(section);
        var options = section.Get<PresidioOptions>(binder => binder.ErrorOnUnknownConfiguration = true) ?? new();
        options.RecognizerDirectory = Path.GetFullPath(options.RecognizerDirectory, baseDirectory);
        string application = Path.TrimEndingDirectorySeparator(Path.GetFullPath(baseDirectory)) + Path.DirectorySeparatorChar;
        if (!options.RecognizerDirectory.StartsWith(application, StringComparison.OrdinalIgnoreCase))
        {
            // Recognizer files ship only inside the reviewed image (PR-005), never from a mounted or other folder.
            throw new InvalidOperationException("Presidio:RecognizerDirectory must be a folder inside the application folder.");
        }
        if (string.IsNullOrWhiteSpace(options.PythonEnvironment))
        {
            options.PythonEnvironment = null;
        }
        else
        {
            options.PythonEnvironment = Path.GetFullPath(options.PythonEnvironment, baseDirectory);
            if (!File.Exists(Path.Combine(options.PythonEnvironment, "pyvenv.cfg")))
            {
                throw new InvalidOperationException("Presidio:PythonEnvironment has no pyvenv.cfg: " + options.PythonEnvironment);
            }
        }
        return options;
    }

    /// <summary>
    /// Stops startup when a retired key is set in the file or as an environment variable. <c>Presidio:DetectionLog</c> is
    /// retired only as a value of its own (true or false); as a section it holds the current settings.
    /// </summary>
    /// <param name="section">The Presidio section.</param>
    /// <exception cref="InvalidOperationException">A retired key is set; the message names the key that replaces it.</exception>
    private static void RejectRetiredKeys(IConfigurationSection section)
    {
        foreach (var (retired, replacement) in RetiredKeys)
        {
            if (section.GetSection(retired).Value is not null)
            {
                throw new InvalidOperationException($"Presidio:{retired} is no longer supported; use {replacement}.");
            }
        }
    }

    #endregion
}
