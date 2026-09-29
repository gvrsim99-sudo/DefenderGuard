using System.Security;
using System.Security.Cryptography;

namespace DemoGuard;

internal sealed record DuplicateCandidate(
    string Path,
    long Length,
    DateTime LastWrite);

internal sealed record DuplicateFile(
    string Path,
    long SizeBytes,
    DateTime LastWriteTime);

internal sealed record DuplicateGroup(
    string Sha256,
    long FileSizeBytes,
    IReadOnlyList<DuplicateFile> Files)
{
    public long ReclaimableBytes => Math.Max(0, FileSizeBytes * Math.Max(0, Files.Count - 1));
}

internal sealed record DuplicateScanResult(
    IReadOnlyList<DuplicateGroup> Groups,
    int FilesScanned,
    int CandidateFiles,
    long ReclaimableBytes);

internal sealed record DuplicateDeletionSelection(string Sha256, string Path, long SizeBytes);

internal sealed record DuplicateDeletionResult(
    int DeletedFiles,
    long DeletedBytes,
    int SkippedFiles,
    long MeasuredFreedBytes,
    int ValidatedGroups,
    int InvalidGroups,
    IReadOnlyList<string> SkippedPaths,
    IReadOnlyList<string> Errors);

internal static class DuplicateFileService
{
    private const int SampleSize = 64 * 1024;

    public static DuplicateScanResult ScanDefaultUserFolders(
        Action<int, string>? progress = null)
    {
        var roots = GetRoots();
        var allFiles = new List<string>();
        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                allFiles.AddRange(Directory.EnumerateFiles(root, "*",
                    new EnumerationOptions
                    {
                        RecurseSubdirectories = true,
                        IgnoreInaccessible = true,
                        ReturnSpecialDirectories = false,
                        AttributesToSkip = FileAttributes.Hidden |
                                           FileAttributes.System |
                                           FileAttributes.ReparsePoint
                    }).Where(path => IsSafeUserFile(root, path)));
            }
            catch { }
        }

        var files = allFiles.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var scanned = 0;
        progress?.Invoke(0, $"Найдено файлов для анализа: {files.Length:N0}");

        var sizeGroups = files
            .Select(TryReadInfo)
            .OfType<DuplicateCandidate>()
            .GroupBy(info => info.Length)
            .Where(group => group.Count() > 1)
            .ToArray();

        var candidateFiles = sizeGroups.Sum(group => group.Count());
        progress?.Invoke(20, $"После группировки по размеру: {candidateFiles:N0} кандидатов.");

        var quickGroups = new List<List<DuplicateCandidate>>();
        foreach (var sizeGroup in sizeGroups)
        {
            var quickMap = new Dictionary<string, List<DuplicateCandidate>>(StringComparer.Ordinal);
            foreach (var info in sizeGroup)
            {
                try
                {
                    var quickHash = ComputeQuickHash(info.Path, info.Length);
                    if (!quickMap.TryGetValue(quickHash, out var list))
                    {
                        list = [];
                        quickMap[quickHash] = list;
                    }
                    list.Add(info);
                }
                catch { }
                scanned++;
                if (scanned % 100 == 0)
                    progress?.Invoke(20 + Math.Min(50, scanned * 50 / Math.Max(1, candidateFiles)),
                        $"Быстрый анализ: {scanned:N0}/{candidateFiles:N0}");
            }

            quickGroups.AddRange(quickMap.Values.Where(list => list.Count > 1));
        }

        progress?.Invoke(72, $"Кандидаты после быстрого отпечатка: {quickGroups.Sum(g => g.Count()):N0}");

        var groups = new List<DuplicateGroup>();
        var completed = 0;
        var totalFull = quickGroups.Sum(group => group.Count());

        foreach (var quickGroup in quickGroups)
        {
            var shaMap = new Dictionary<string, List<DuplicateFile>>(StringComparer.OrdinalIgnoreCase);
            foreach (var info in quickGroup)
            {
                try
                {
                    var sha = ComputeSha256(info.Path);
                    if (!shaMap.TryGetValue(sha, out var list))
                    {
                        list = [];
                        shaMap[sha] = list;
                    }
                    list.Add(new DuplicateFile(info.Path, info.Length, info.LastWrite));
                }
                catch { }

                completed++;
                if (completed % 20 == 0)
                    progress?.Invoke(72 + Math.Min(28, completed * 28 / Math.Max(1, totalFull)),
                        $"SHA-256: {completed:N0}/{totalFull:N0}");
            }

            foreach (var pair in shaMap.Where(pair => pair.Value.Count > 1))
                groups.Add(new DuplicateGroup(pair.Key, pair.Value[0].SizeBytes, pair.Value
                    .OrderBy(file => file.Path.Length)
                    .ThenBy(file => file.LastWriteTime)
                    .ToArray()));
        }

        var ordered = groups
            .OrderByDescending(group => group.ReclaimableBytes)
            .ThenByDescending(group => group.FileSizeBytes)
            .ToArray();

        progress?.Invoke(100,
            $"Готово: {ordered.Length:N0} групп дубликатов, потенциально {FormatBytes(ordered.Sum(g => g.ReclaimableBytes))}.");

        return new DuplicateScanResult(
            ordered,
            files.Length,
            candidateFiles,
            ordered.Sum(group => group.ReclaimableBytes));
    }

    public static bool CanDeleteDuplicate(string path)
        => IsSafeDuplicateDeletionPath(path);

    public static DuplicateDeletionResult DeleteSelectedDuplicates(
        DuplicateScanResult scan,
        IReadOnlyCollection<DuplicateDeletionSelection> selections)
    {
        var selected = selections
            .GroupBy(item => NormalizePath(item.Path), StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToArray();
        if (selected.Length == 0)
            return new DuplicateDeletionResult(0, 0, 0, 0, 0, 0, Array.Empty<string>(), Array.Empty<string>());

        var selectedByKey = selected.ToDictionary(
            item => BuildSelectionKey(item.Sha256, item.Path, item.SizeBytes),
            item => item,
            StringComparer.OrdinalIgnoreCase);
        var beforeSpace = CaptureDriveFreeSpace(selected.Select(item => item.Path));
        var skippedPaths = new List<string>();
        var errors = new List<string>();
        var deletedFiles = 0;
        long deletedBytes = 0;
        var affectedGroups = new List<DuplicateGroup>();

        foreach (var group in scan.Groups)
        {
            var groupSelections = group.Files
                .Where(file => selectedByKey.ContainsKey(BuildSelectionKey(group.Sha256, file.Path, file.SizeBytes)))
                .ToArray();
            if (groupSelections.Length == 0) continue;

            var keeper = group.Files
                .Where(file => !selectedByKey.ContainsKey(BuildSelectionKey(group.Sha256, file.Path, file.SizeBytes)))
                .FirstOrDefault(file => MatchesExpectedFile(file.Path, group.Sha256, group.FileSizeBytes));
            if (keeper is null)
            {
                foreach (var file in groupSelections)
                    skippedPaths.Add(file.Path);
                errors.Add($"Группа {group.Sha256}: не найден надёжный оставляемый экземпляр. Удаление группы отменено.");
                continue;
            }

            affectedGroups.Add(group);
            foreach (var file in groupSelections)
            {
                if (!MatchesExpectedFile(keeper.Path, group.Sha256, group.FileSizeBytes))
                {
                    skippedPaths.Add(file.Path);
                    errors.Add($"Оставляемый экземпляр группы изменился или исчез; удаление остановлено для группы: {group.Sha256}");
                    continue;
                }

                if (!IsSafeDuplicateDeletionPath(file.Path))
                {
                    skippedPaths.Add(file.Path);
                    errors.Add($"Защищённый или недопустимый путь: {file.Path}");
                    continue;
                }

                if (!MatchesExpectedFile(file.Path, group.Sha256, group.FileSizeBytes))
                {
                    skippedPaths.Add(file.Path);
                    errors.Add($"Файл изменился после сканирования, удаление пропущено: {file.Path}");
                    continue;
                }

                try
                {
                    File.Delete(file.Path);
                    deletedFiles++;
                    deletedBytes += file.SizeBytes;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
                {
                    skippedPaths.Add(file.Path);
                    errors.Add($"Не удалось удалить {file.Path}: {ex.Message}");
                }
            }
        }

        var validatedGroups = 0;
        var invalidGroups = 0;
        foreach (var group in affectedGroups.DistinctBy(item => item.Sha256))
        {
            var surviving = group.Files.Any(file => MatchesExpectedFile(file.Path, group.Sha256, group.FileSizeBytes));
            if (surviving)
                validatedGroups++;
            else
            {
                invalidGroups++;
                errors.Add($"После удаления не найден ни один подтверждённый экземпляр группы: {group.Sha256}");
            }
        }

        var afterSpace = CaptureDriveFreeSpace(selected.Select(item => item.Path));
        long measuredFreedBytes = 0;
        foreach (var pair in beforeSpace)
        {
            if (afterSpace.TryGetValue(pair.Key, out var after))
                measuredFreedBytes += Math.Max(0, pair.Value - after);
        }

        return new DuplicateDeletionResult(
            deletedFiles,
            deletedBytes,
            skippedPaths.Count,
            measuredFreedBytes,
            validatedGroups,
            invalidGroups,
            skippedPaths.Distinct(StringComparer.OrdinalIgnoreCase).Take(100).ToArray(),
            errors.Distinct(StringComparer.Ordinal).Take(100).ToArray());
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} Б";
        if (bytes < 1024 * 1024) return $"{bytes / 1024d:0.0} КБ";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024d / 1024d:0.0} МБ";
        return $"{bytes / 1024d / 1024d / 1024d:0.00} ГБ";
    }

    private static bool MatchesExpectedFile(string path, string expectedSha256, long expectedSize)
    {
        try
        {
            var full = NormalizePath(path);
            var attributes = File.GetAttributes(full);
            if ((attributes & FileAttributes.ReparsePoint) != 0) return false;
            var info = new FileInfo(full);
            if (!info.Exists || info.Length != expectedSize) return false;
            return string.Equals(ComputeSha256(full), expectedSha256, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private static bool IsSafeDuplicateDeletionPath(string path)
    {
        try
        {
            var full = NormalizePath(path);
            if (!GetRoots().Any(root => full.StartsWith(EnsureTrailingSeparator(NormalizePath(root)), StringComparison.OrdinalIgnoreCase)))
                return false;
            var attributes = File.GetAttributes(full);
            if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Hidden | FileAttributes.System)) != 0)
                return false;

            var extension = Path.GetExtension(full);
            if (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".msi", StringComparison.OrdinalIgnoreCase))
                return false;

            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var buildRoot = NormalizePath(Path.Combine(profile, "Downloads", "DG-build-check"));
            if (full.StartsWith(EnsureTrailingSeparator(buildRoot), StringComparison.OrdinalIgnoreCase))
                return false;

            var programDataDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Rockstar Games", "Steam", "Epic Games", "EA Games", "Electronic Arts",
                "Ubisoft", "Battle.net", "NVIDIA", "AMD", "Unity", "Unreal Engine"
            };
            var protectedFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Login Data", "Cookies", "History", "Web Data", "Local State", "Preferences"
            };
            var root = GetRoots().FirstOrDefault(item =>
                full.StartsWith(EnsureTrailingSeparator(NormalizePath(item)), StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(root))
            {
                var relative = Path.GetRelativePath(NormalizePath(root), full);
                var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar,
                    StringSplitOptions.RemoveEmptyEntries);
                if (parts.Take(Math.Max(0, parts.Length - 1)).Any(programDataDirectories.Contains))
                    return false;
                if (protectedFileNames.Contains(parts.LastOrDefault() ?? string.Empty))
                    return false;
            }

            var currentExecutable = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(currentExecutable) &&
                full.Equals(NormalizePath(currentExecutable), StringComparison.OrdinalIgnoreCase))
                return false;

            return true;
        }
        catch { return false; }
    }

    private static Dictionary<string, long> CaptureDriveFreeSpace(IEnumerable<string> paths)
    {
        var result = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            try
            {
                var root = Path.GetPathRoot(NormalizePath(path));
                if (string.IsNullOrWhiteSpace(root)) continue;
                result[root] = new DriveInfo(root).AvailableFreeSpace;
            }
            catch { }
        }
        return result;
    }

    private static string BuildSelectionKey(string sha256, string path, long size)
        => $"{sha256}:{size}:{NormalizePath(path)}";

    private static string NormalizePath(string path)
        => Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);

    private static string EnsureTrailingSeparator(string path)
        => path.EndsWith(Path.DirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;

    private static string[] GetRoots()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
            Environment.GetFolderPath(Environment.SpecialFolder.MyVideos),
            Environment.GetFolderPath(Environment.SpecialFolder.MyMusic)
        }
        .Where(path => !string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
    }

    private static DuplicateCandidate? TryReadInfo(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0) return null;
            return new DuplicateCandidate(info.FullName, info.Length, info.LastWriteTime);
        }
        catch { return null; }
    }

    private static string ComputeQuickHash(string path, long length)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, SampleSize, FileOptions.SequentialScan);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var buffer = new byte[Math.Min(SampleSize, Math.Max(1, length))];
        var firstRead = stream.Read(buffer, 0, buffer.Length);
        sha.AppendData(buffer, 0, firstRead);

        if (length > SampleSize)
        {
            stream.Seek(Math.Max(0, length - SampleSize), SeekOrigin.Begin);
            var lastRead = stream.Read(buffer, 0, buffer.Length);
            sha.AppendData(buffer, 0, lastRead);
        }

        Span<byte> lengthBytes = stackalloc byte[8];
        BitConverter.TryWriteBytes(lengthBytes, length);
        sha.AppendData(lengthBytes);
        return Convert.ToHexString(sha.GetHashAndReset());
    }

    private static string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 128 * 1024, FileOptions.SequentialScan);
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream));
    }

    private static bool IsSafeUserFile(string root, string path)
    {
        try
        {
            var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) +
                           Path.DirectorySeparatorChar;
            var full = Path.GetFullPath(path);
            if (!full.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase)) return false;

            var relative = Path.GetRelativePath(fullRoot, full);
            var normalized = relative.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
            var parts = normalized.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
            var excludedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".git", ".vs", "bin", "obj", "node_modules", "Cache", "Cache_Data",
                "cache2", "Code Cache", "GPUCache", "CachedData"
            };
            if (parts.Take(parts.Length - 1).Any(part => excludedDirectories.Contains(part)))
                return false;

            var extension = Path.GetExtension(full);
            if (extension.Equals(".tmp", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".log", StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(".dmp", StringComparison.OrdinalIgnoreCase))
                return false;

            var attributes = File.GetAttributes(full);
            return (attributes & (FileAttributes.ReparsePoint |
                                  FileAttributes.Hidden |
                                  FileAttributes.System)) == 0;
        }
        catch { return false; }
    }
}