using PresidioDemo.Core.Models;
using PresidioDemo.Core.Protection;

namespace PresidioDemo.DetectionParity;

/// <summary>
/// Checks that the five recognizer files load and that invalid files stop startup (V-04, WR-014).
/// </summary>
public static class ConfigurationChecks
{

    #region Methods

    /// <summary>
    /// Runs every configuration check and prints one value-free line per check.
    /// </summary>
    /// <param name="root">The repository root.</param>
    /// <returns>The number of checks that passed.</returns>
    /// <exception cref="Exception">A check failed.</exception>
    public static int Run(string root)
    {
        string directory = Path.Combine(root, "src", "PresidioDemo.Core", "Configuration", "recognizers");
        var sets = RecognizerConfiguration.Load(directory);
        int passed = 0;
        Check(sets.Count == FeedCatalog.All.Count && sets.ContainsKey(FeedType.PNR), "the PNR recognizer file loads", ref passed);
        foreach (var (feed, set) in sets)
        {
            Check(set.Anchors.Count > 0, FeedCatalog.Get(feed).FolderName + " declares a PNR anchor", ref passed);
        }
        Check(sets[FeedType.PNR].Formats.Any(f => f.Entity == "DATE_OF_BIRTH") && sets.Values.All(s => s.Formats.Any(f => f.Entity == "PERSON")),
            "date-of-birth and passenger-name formats are declared", ref passed);
        var baseline = ParityBaseline.Load(root);
        var uncovered = UncoveredEntities(baseline, sets);
        Check(uncovered.Count == 0, "every baseline entity has a format or built-in in its feed's file"
            + (uncovered.Count == 0 ? "" : ": missing " + string.Join(", ", uncovered)), ref passed);
        var withoutDateOfBirth = new Dictionary<FeedType, FeedRecognizerSet>(sets)
        {
            [FeedType.PNR] = sets[FeedType.PNR] with { Formats = sets[FeedType.PNR].Formats.Where(f => f.Entity != "DATE_OF_BIRTH").ToArray() },
        };
        Check(UncoveredEntities(baseline, withoutDateOfBirth).Contains("PNR DATE_OF_BIRTH"),
            "the coverage check reports a baseline entity removed from its feed's file", ref passed);

        string scratch = Path.Combine(Path.GetTempPath(), "recognizer-checks-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        try
        {
            string valid = File.ReadAllText(Path.Combine(directory, "pnr.xml"));
            Reject(scratch, "<recognizers feed=\"PNR\"", "not well-formed XML", ref passed);
            Reject(scratch, "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x \"y\">]><recognizers feed=\"PNR\"><pnrAnchor after=\"a\" /></recognizers>", "a DTD", ref passed);
            Reject(scratch, valid.Replace("feed=\"PNR\"", "feed=\"OTHER\""), "the wrong feed attribute", ref passed);
            Reject(scratch, valid.Replace("<pattern>^\\d{9}$</pattern>", "<pattern>(unclosed</pattern>"), "a pattern that does not compile", ref passed);
            Reject(scratch, valid.Replace("name=\"memberName\"", "name=\"passengerName\""), "a duplicate name", ref passed);
            Reject(scratch, valid.Replace("<pnrAnchor after=\"creationTime\" offset=\"1\" />", ""), "a missing PNR anchor", ref passed);
            Reject(scratch, valid.Replace("after=\"creationTime\"", "after=\"noSuchFormat\""), "an anchor neighbour that does not exist", ref passed);
            Reject(scratch, valid.Replace("<format name=\"creationTime\" entity=\"UNCLASSIFIED_IDENTIFIER\" score=\"0.85\" maskCharacter=\"*\">",
                "<format name=\"creationTime\" entity=\"UNCLASSIFIED_IDENTIFIER\" action=\"Replace\" replacement=\"[X]\">"), "Replace in a binary feed", ref passed);
            Reject(scratch, valid.Replace("<builtIn entity=\"PERSON\" />", "<builtIn entity=\"PASSPORT\" />"), "an unsupported built-in", ref passed);
            Reject(scratch, valid.Replace("<keep name=\"time\">", "<keep name=\"time\" colour=\"red\">"), "an unknown attribute", ref passed);
            Reject(scratch, valid.Replace("<keep name=\"time\"><pattern>\\d{4}</pattern></keep>", "<keep name=\"time\"><pattern>\\d{4}</pattern></keep><rule />"), "an unknown element", ref passed);
            Reject(scratch, valid.Replace("<keep name=\"time\"><pattern>\\d{4}</pattern></keep>", "<keep name=\"time\"><key>Time</key></keep>"), "a key in a binary feed", ref passed);
            Reject(scratch, valid.Replace("defaultMaskCharacter=\"#\"", "defaultMaskCharacter=\"##\""), "a two-character mask", ref passed);
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
        return passed;
    }

    /// <summary>
    /// Returns each feed and entity of the frozen baseline that no format or built-in of that feed's recognizer file
    /// declares (AC-004, WR-014). The fallback mask is not counted, so every protected entity type has a named recognizer.
    /// </summary>
    /// <param name="baseline">The frozen parity baseline.</param>
    /// <param name="sets">The recognizer sets by feed.</param>
    /// <returns>Value-free <c>feed entity</c> labels, sorted; empty when every entity is covered.</returns>
    public static IReadOnlyList<string> UncoveredEntities(ParityBaselineDocument baseline, IReadOnlyDictionary<FeedType, FeedRecognizerSet> sets) =>
        baseline.Protected
            .Select(e => (Type: FeedCatalog.All.Single(f => f.FolderName == e.Feed).Type, Name: e.Feed, e.Entity))
            .Distinct()
            .Where(e => !sets[e.Type].Formats.Any(f => f.Entity == e.Entity) && !sets[e.Type].BuiltIns.Any(b => b.Entity == e.Entity))
            .Select(e => e.Name + " " + e.Entity)
            .Order(StringComparer.Ordinal)
            .ToArray();

    /// <summary>
    /// Writes an invalid PNR file and requires the loader to reject it with a value-free message naming the file.
    /// </summary>
    /// <param name="scratch">The temporary directory.</param>
    /// <param name="content">The file content.</param>
    /// <param name="label">What is invalid.</param>
    /// <param name="passed">The passed-check counter.</param>
    private static void Reject(string scratch, string content, string label, ref int passed)
    {
        string path = Path.Combine(scratch, "pnr.xml");
        File.WriteAllText(path, content);
        try
        {
            RecognizerConfiguration.LoadFile(path, FeedType.PNR);
        }
        catch (InvalidDataException ex) when (ex.Message.StartsWith("Recognizer file pnr.xml", StringComparison.Ordinal))
        {
            Console.WriteLine("PASS rejected " + label + " (" + ex.Message + ")");
            passed++;
            return;
        }
        throw new Exception("Expected the loader to reject " + label);
    }

    /// <summary>
    /// Requires a condition.
    /// </summary>
    /// <param name="condition">The condition.</param>
    /// <param name="label">The check name.</param>
    /// <param name="passed">The passed-check counter.</param>
    private static void Check(bool condition, string label, ref int passed)
    {
        if (!condition)
        {
            throw new Exception(label);
        }
        Console.WriteLine("PASS " + label);
        passed++;
    }

    #endregion
}
