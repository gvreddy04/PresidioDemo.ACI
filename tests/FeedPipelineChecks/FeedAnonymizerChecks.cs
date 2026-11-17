using PresidioDemo.Core.Protection;

/// <summary>
/// Checks the configured operators and their width fitting (WR-015): every result is exactly as wide as the text it
/// replaces, and parameters follow Presidio's names. All values are made up.
/// </summary>
internal static class FeedAnonymizerChecks
{

    #region Methods

    /// <summary>
    /// Runs the checks; they need no Presidio engine.
    /// </summary>
    public static void Run()
    {
        var none = new Dictionary<string, string>(StringComparer.Ordinal);
        AnonymizedSpan Apply(string type, string text, Dictionary<string, string>? parameters = null, string entity = "PERSON") =>
            FeedAnonymizer.Apply(FeedAnonymizer.Create(entity, type, parameters ?? none), entity, text);

        Check(Apply("mask", "Alex Sample") == new AnonymizedSpan("***********", false), "mask covers the whole span with * by default");
        Check(Apply("mask", "DA12345678", new() { ["masking_char"] = "#" }).Text == "##########", "mask uses masking_char");
        Check(Apply("mask", "4111111111111111", new() { ["chars_to_mask"] = "12" }).Text == "************1111", "mask changes chars_to_mask characters from the start");
        Check(Apply("mask", "4111111111111111", new() { ["chars_to_mask"] = "4", ["from_end"] = "true" }).Text == "411111111111****", "mask from_end changes the last characters");
        Check(Apply("mask", "Li Wu", new() { ["chars_to_mask"] = "99" }).Text == "*****", "chars_to_mask beyond the span masks all of it");

        Check(Apply("replace", "Alex Sample") == new AnonymizedSpan("<PERSON>   ", false), "replace defaults to <ENTITY>, padded with spaces");
        Check(Apply("replace", "Li Wu") == new AnonymizedSpan("<PERS", true), "a longer replacement is cut to the span and reported as cut");
        Check(Apply("replace", "alex@example.com", entity: "EMAIL_ADDRESS") == new AnonymizedSpan("<EMAIL_ADDRESS> ", false),
            "replace fits the 15-character <EMAIL_ADDRESS> into a 16-character span with one space");
        Check(Apply("replace", "Alex Sample", new() { ["new_value"] = "[NAME]" }).Text == "[NAME]     ", "replace uses new_value");

        Check(Apply("redact", "Alex Sample") == new AnonymizedSpan("           ", false), "redact leaves spaces of the same width");
        Check(Apply("keep", "Alex Sample") == new AnonymizedSpan("Alex Sample", false), "keep leaves the text unchanged");

        var salted = new Dictionary<string, string>(StringComparer.Ordinal) { ["salt"] = "demo-salt" };
        var hashed = Apply("hash", "Alex Sample", salted);
        Check(hashed.Text.Length == 11 && hashed.Text.All(c => char.IsAsciiHexDigitLower(c) || char.IsAsciiDigit(c)) && hashed.Cut,
            "hash writes lowercase hex cut to the span width");
        Check(Apply("hash", "Alex Sample", salted).Text == hashed.Text, "a configured salt hashes equal values alike");
        Check(Apply("hash", "Alex Sample", new() { ["hash_type"] = "sha512", ["salt"] = "demo-salt" }).Text != hashed.Text, "sha512 differs from sha256");
        Check(Enumerable.Range(0, 5).Select(_ => Apply("hash", "Alex Sample").Text).Distinct().Count() > 1, "without a salt each value gets a random salt");

        foreach (string rejected in new[] { "encrypt", "custom", "surrogate_ahds" })
        {
            Rejects(() => FeedAnonymizer.Create("PERSON", rejected, none), $"operator '{rejected}' is not allowed", rejected + " is rejected");
        }
        Rejects(() => FeedAnonymizer.Create("PERSON", "scramble", none), "operator 'scramble' is not supported", "an unknown operator is rejected");
        Rejects(() => FeedAnonymizer.Create("PERSON", "mask", new Dictionary<string, string> { ["new_value"] = "X" }), "operator 'mask' has no parameter 'new_value'", "a parameter of another operator is rejected");
        Rejects(() => FeedAnonymizer.Create("PERSON", "mask", new Dictionary<string, string> { ["masking_char"] = "**" }), "masking_char must be", "a two-character masking_char is rejected");
        Rejects(() => FeedAnonymizer.Create("PERSON", "mask", new Dictionary<string, string> { ["chars_to_mask"] = "0" }), "chars_to_mask must be", "chars_to_mask 0 is rejected");
        Rejects(() => FeedAnonymizer.Create("PERSON", "hash", new Dictionary<string, string> { ["hash_type"] = "md5" }), "hash_type must be", "an unsupported hash_type is rejected");
        Rejects(() => FeedAnonymizer.Create("PERSON", "replace", new Dictionary<string, string> { ["new_value"] = "café" }), "new_value must be", "a non-ASCII new_value is rejected");
        Console.WriteLine("PASS operator and width-fitting checks");
    }

    /// <summary>
    /// Requires a format error whose message contains the expected text.
    /// </summary>
    private static void Rejects(Action action, string expected, string label)
    {
        try
        {
            action();
        }
        catch (FormatException ex) when (ex.Message.Contains(expected, StringComparison.Ordinal))
        {
            Console.WriteLine("PASS " + label);
            return;
        }
        throw new InvalidOperationException("FAIL " + label);
    }

    /// <summary>
    /// Throws when a condition fails.
    /// </summary>
    private static void Check(bool condition, string label)
    {
        if (!condition)
        {
            throw new InvalidOperationException("FAIL " + label);
        }
        Console.WriteLine("PASS " + label);
    }

    #endregion
}
