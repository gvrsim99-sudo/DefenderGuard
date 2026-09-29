using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DemoGuard;

internal enum LocalFileListKind
{
    Blacklist,
    Whitelist
}

internal enum LocalFileListMatch
{
    None,
    Blacklist,
    Whitelist
}

internal sealed record LocalFileRule(string Sha256, string Note, DateTime AddedAt);
internal sealed record LocalFileLists(List<LocalFileRule> Blacklist, List<LocalFileRule> Whitelist);
internal sealed record LocalFileAnalysisResult(
    string Path,
    string? Sha256,
    LocalFileListMatch ListMatch,
    HeuristicFinding? Heuristic,
    bool HeuristicSuppressedByWhitelist,
    int? DefenderExitCode,
    string DefenderOutput,
    string? Error,
    DateTime AnalyzedAt);

internal static class FileRuleStore
{
    private static readonly object Sync = new();
    private static readonly string DataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DemoGuard");
    private static readonly string DataPath = Path.Combine(DataDirectory, "file-lists.json");
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

    public static LocalFileLists Load()
    {
        lock (Sync) return LoadUnlocked();
    }

    public static string ComputeSha256(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Не указан путь к файлу.", nameof(path));
        using var stream = new FileStream(Path.GetFullPath(path), FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Delete, 128 * 1024, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    public static LocalFileListMatch Classify(string? sha256, LocalFileLists? snapshot = null)
    {
        if (!TryNormalizeSha256(sha256, out var normalized)) return LocalFileListMatch.None;
        var lists = snapshot ?? Load();
        if (lists.Blacklist.Any(rule => rule.Sha256.Equals(normalized, StringComparison.OrdinalIgnoreCase)))
            return LocalFileListMatch.Blacklist;
        if (lists.Whitelist.Any(rule => rule.Sha256.Equals(normalized, StringComparison.OrdinalIgnoreCase)))
            return LocalFileListMatch.Whitelist;
        return LocalFileListMatch.None;
    }

    public static void AddHash(string sha256, LocalFileListKind list, string? note)
    {
        if (!TryNormalizeSha256(sha256, out var normalized))
            throw new ArgumentException("SHA-256 должен содержать ровно 64 шестнадцатеричных символа.", nameof(sha256));

        lock (Sync)
        {
            var current = LoadUnlocked();
            current.Blacklist.RemoveAll(rule => rule.Sha256.Equals(normalized, StringComparison.OrdinalIgnoreCase));
            current.Whitelist.RemoveAll(rule => rule.Sha256.Equals(normalized, StringComparison.OrdinalIgnoreCase));
            var description = string.IsNullOrWhiteSpace(note) ? "Пользовательское правило" : note.Trim();
            if (description.Length > 200) description = description[..200];
            var entry = new LocalFileRule(normalized, description, DateTime.Now);
            (list == LocalFileListKind.Blacklist ? current.Blacklist : current.Whitelist).Insert(0, entry);
            SaveUnlocked(current);
        }
    }

    public static bool RemoveHash(string sha256)
    {
        if (!TryNormalizeSha256(sha256, out var normalized)) return false;
        lock (Sync)
        {
            var current = LoadUnlocked();
            var removed = current.Blacklist.RemoveAll(rule => rule.Sha256.Equals(normalized, StringComparison.OrdinalIgnoreCase))
                + current.Whitelist.RemoveAll(rule => rule.Sha256.Equals(normalized, StringComparison.OrdinalIgnoreCase));
            if (removed > 0) SaveUnlocked(current);
            return removed > 0;
        }
    }

    public static bool TryNormalizeSha256(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (value is null) return false;
        var candidate = value.Trim();
        if (candidate.Length != 64 || candidate.Any(character => !Uri.IsHexDigit(character))) return false;
        normalized = candidate.ToUpperInvariant();
        return true;
    }

    private static LocalFileLists LoadUnlocked()
    {
        if (!File.Exists(DataPath)) return Empty();
        try
        {
            var parsed = JsonSerializer.Deserialize<LocalFileLists>(File.ReadAllText(DataPath), JsonOptions);
            if (parsed is null) throw new InvalidDataException("Файл списков пуст или содержит неверный формат.");
            var blacklist = Sanitize(parsed.Blacklist);
            var blockedHashes = blacklist.Select(rule => rule.Sha256).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var whitelist = Sanitize(parsed.Whitelist).Where(rule => !blockedHashes.Contains(rule.Sha256)).ToList();
            return new LocalFileLists(blacklist, whitelist);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            throw new InvalidDataException("Не удалось прочитать локальные списки SHA-256. Исходный файл правил сохранён без изменений.", ex);
        }
    }

    private static List<LocalFileRule> Sanitize(IEnumerable<LocalFileRule>? rules)
    {
        if (rules is null) return [];
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<LocalFileRule>();
        foreach (var item in rules)
        {
            if (item is null || !TryNormalizeSha256(item.Sha256, out var normalized) || !seen.Add(normalized)) continue;
            var note = string.IsNullOrWhiteSpace(item.Note) ? "Пользовательское правило" : item.Note.Trim();
            if (note.Length > 200) note = note[..200];
            result.Add(item with { Sha256 = normalized, Note = note });
        }
        return result.OrderByDescending(item => item.AddedAt).ToList();
    }

    private static void SaveUnlocked(LocalFileLists lists)
    {
        Directory.CreateDirectory(DataDirectory);
        var temporaryPath = DataPath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(lists, JsonOptions), new UTF8Encoding(false));
        File.Move(temporaryPath, DataPath, overwrite: true);
    }

    private static LocalFileLists Empty() => new([], []);
}