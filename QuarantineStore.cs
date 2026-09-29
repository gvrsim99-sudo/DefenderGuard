using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DemoGuard;

internal sealed record QuarantinedFile(
    string Id,
    string OriginalPath,
    string StoredPath,
    DateTime QuarantinedAt,
    string OriginalName,
    long Length,
    string Sha256,
    int OriginalAttributes,
    DateTime OriginalLastWriteTimeUtc);

internal sealed record QuarantineRestoreResult(string RestoredPath, bool RemovedFromQuarantine);

internal static class QuarantineStore
{
    private const int BufferSize = 128 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static QuarantinedFile Add(string sourcePath, string quarantineDirectory, string? expectedSha256 = null)
    {
        var source = Path.GetFullPath(sourcePath);
        if (!File.Exists(source)) throw new FileNotFoundException("Выбранный файл не найден.", source);
        if (expectedSha256 is not null && (expectedSha256.Length != 64 || expectedSha256.Any(character => !Uri.IsHexDigit(character))))
            throw new ArgumentException("Ожидаемый SHA-256 должен состоять ровно из 64 шестнадцатеричных символов.", nameof(expectedSha256));
        EnsureSafeSourcePath(source, quarantineDirectory);

        var attributes = File.GetAttributes(source);
        if ((attributes & FileAttributes.Directory) != 0) throw new IOException("Помещать папки в карантин нельзя; выберите отдельные файлы.");
        if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Символические ссылки и другие reparse-point файлы не принимаются.");

        Directory.CreateDirectory(quarantineDirectory);
        EnsureNoReparsePointInParents(quarantineDirectory);
        var id = Guid.NewGuid().ToString("N");
        var stagedPath = Path.Combine(quarantineDirectory, id + ".stage");
        var storedPath = StoredPathFor(quarantineDirectory, id);
        var metadataPath = MetadataPathFor(quarantineDirectory, id);
        var metadataWritten = false;

        try
        {
            using var input = SafeFileAccess.OpenRegularFileRead(source, BufferSize);
            var originalLength = input.Length;
            var originalLastWriteTimeUtc = File.GetLastWriteTimeUtc(source);
            string sha256;
            using (var output = new FileStream(stagedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, BufferSize, FileOptions.WriteThrough))
            {
                using var sourceHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[BufferSize];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sourceHash.AppendData(buffer, 0, read);
                    output.Write(buffer, 0, read);
                }
                output.Flush(flushToDisk: true);
                sha256 = Convert.ToHexString(sourceHash.GetHashAndReset());
            }
            if (new FileInfo(stagedPath).Length != originalLength || !HashMatches(stagedPath, sha256))
                throw new IOException("Проверка длины или SHA-256 копии не прошла; исходный файл оставлен на месте.");
            if (expectedSha256 is not null && !sha256.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Файл изменился после анализа: SHA-256 не совпадает с результатом сканирования. Исходный файл оставлен на месте.");

            if (OperatingSystem.IsWindows())
                File.SetAttributes(stagedPath, FileAttributes.NotContentIndexed);
            File.Move(stagedPath, storedPath, overwrite: false);

            var item = new QuarantinedFile(
                id,
                source,
                storedPath,
                DateTime.Now,
                Path.GetFileName(source),
                originalLength,
                sha256,
                (int)attributes,
                originalLastWriteTimeUtc);
            WriteMetadata(item, quarantineDirectory, overwrite: false);
            metadataWritten = true;

            try
            {
                // The input handle allows delete-sharing but denies concurrent writes while the copy is made.
                File.Delete(source);
            }
            catch (Exception ex)
            {
                throw new IOException("Копия помещена в карантин, но Windows не разрешила удалить оригинал. Оригинал оставлен; проверьте список карантина.", ex);
            }
            return item;
        }
        catch
        {
            TryDelete(stagedPath);
            if (!metadataWritten)
            {
                TryDelete(storedPath);
                TryDelete(metadataPath);
            }
            throw;
        }
    }

    public static List<QuarantinedFile> Load(string quarantineDirectory)
    {
        Directory.CreateDirectory(quarantineDirectory);
        var items = new List<QuarantinedFile>();
        foreach (var metadataPath in Directory.EnumerateFiles(quarantineDirectory, "*.json"))
        {
            try
            {
                var json = File.ReadAllText(metadataPath);
                var item = JsonSerializer.Deserialize<QuarantinedFile>(json);
                if (item is null || !Guid.TryParseExact(item.Id, "N", out _)) continue;
                if (!string.Equals(Path.GetFileNameWithoutExtension(metadataPath), item.Id, StringComparison.OrdinalIgnoreCase)) continue;

                var expectedStoredPath = StoredPathFor(quarantineDirectory, item.Id);
                if (!PathEquals(item.StoredPath, expectedStoredPath)) continue;
                if (string.IsNullOrWhiteSpace(item.OriginalPath) || !Path.IsPathRooted(item.OriginalPath)) continue;

                // Migrate records created by the earlier EICAR-only prototype.
                if (item.QuarantinedAt == default && TryReadLegacyDate(json, out var legacyDate))
                    item = item with { QuarantinedAt = legacyDate };
                if (File.Exists(expectedStoredPath) && (item.Length < 0 || string.IsNullOrWhiteSpace(item.Sha256)))
                {
                    var info = new FileInfo(expectedStoredPath);
                    item = item with
                    {
                        StoredPath = expectedStoredPath,
                        Length = info.Length,
                        Sha256 = ComputeSha256(expectedStoredPath)
                    };
                    try { WriteMetadata(item, quarantineDirectory, overwrite: true); } catch { }
                }
                else
                {
                    item = item with { StoredPath = expectedStoredPath };
                }

                items.Add(item);
            }
            catch
            {
                // Ignore malformed metadata; never use it as an arbitrary filesystem path.
            }
        }
        return items.OrderByDescending(item => item.QuarantinedAt).ToList();
    }

    public static bool VerifyStoredFile(QuarantinedFile item, string quarantineDirectory, out string reason)
    {
        if (!TryValidateItem(item, quarantineDirectory, out var storedPath, out _, out reason)) return false;
        if (!File.Exists(storedPath))
        {
            reason = "Файл отсутствует в локальном карантине. Проверьте Историю защиты Windows — Defender мог переместить его в собственный карантин.";
            return false;
        }
        try
        {
            var info = new FileInfo(storedPath);
            if (info.Length != item.Length)
            {
                reason = "Размер файла карантина изменился; восстановление запрещено.";
                return false;
            }
            if (!HashMatches(storedPath, item.Sha256))
            {
                reason = "SHA-256 файла карантина не совпадает с сохранённой контрольной суммой; восстановление запрещено.";
                return false;
            }
            reason = string.Empty;
            return true;
        }
        catch (Exception ex)
        {
            reason = "Не удалось проверить файл карантина: " + ex.Message;
            return false;
        }
    }

    public static QuarantineRestoreResult Restore(QuarantinedFile item, string quarantineDirectory)
    {
        if (!VerifyStoredFile(item, quarantineDirectory, out var reason)) throw new IOException(reason);
        if (!TryValidateItem(item, quarantineDirectory, out var storedPath, out var metadataPath, out reason)) throw new IOException(reason);

        var originalPath = Path.GetFullPath(item.OriginalPath);
        EnsureNotWindowsDirectory(originalPath);
        var destinationDirectory = Path.GetDirectoryName(originalPath);
        if (string.IsNullOrWhiteSpace(destinationDirectory)) throw new IOException("Не удалось определить исходную папку.");
        Directory.CreateDirectory(destinationDirectory);
        EnsureNoReparsePointInParents(destinationDirectory);

        var restoreTemp = Path.Combine(destinationDirectory, ".DefenderGuard-restore-" + item.Id + ".tmp");
        TryDelete(restoreTemp);
        try
        {
            using (var input = SafeFileAccess.OpenRegularFileRead(storedPath, BufferSize))
            using (var output = new FileStream(restoreTemp, FileMode.CreateNew, FileAccess.Write, FileShare.None, BufferSize, FileOptions.WriteThrough))
            {
                input.CopyTo(output, BufferSize);
                output.Flush(flushToDisk: true);
            }

            if (new FileInfo(restoreTemp).Length != item.Length || !HashMatches(restoreTemp, item.Sha256))
                throw new IOException("SHA-256 временной копии не совпадает; исходный файл не восстановлен.");

            if (item.OriginalLastWriteTimeUtc != default)
                File.SetLastWriteTimeUtc(restoreTemp, item.OriginalLastWriteTimeUtc);
            File.SetAttributes(restoreTemp, RestoreAttributes(item.OriginalAttributes));

            var destination = originalPath;
            for (var attempt = 0; attempt < 100; attempt++)
            {
                if (File.Exists(destination) || Directory.Exists(destination))
                    destination = ConflictPath(originalPath, item.Id, attempt);
                try
                {
                    File.Move(restoreTemp, destination, overwrite: false);
                    break;
                }
                catch (IOException) when (File.Exists(destination) || Directory.Exists(destination))
                {
                    destination = ConflictPath(originalPath, item.Id, attempt + 1);
                }
                if (attempt == 99) throw new IOException("Не удалось подобрать свободное имя файла для восстановления.");
            }

            var removed = false;
            try
            {
                File.Delete(storedPath);
                File.Delete(metadataPath);
                removed = true;
            }
            catch
            {
                // The restored copy is already verified; leave the quarantine copy if cleanup fails.
            }
            return new QuarantineRestoreResult(destination, removed);
        }
        catch
        {
            TryDelete(restoreTemp);
            throw;
        }
    }

    public static void Delete(QuarantinedFile item, string quarantineDirectory)
    {
        if (!TryValidateItem(item, quarantineDirectory, out var storedPath, out var metadataPath, out var reason))
            throw new IOException(reason);
        if (File.Exists(storedPath)) File.Delete(storedPath);
        if (File.Exists(metadataPath)) File.Delete(metadataPath);
    }

    private static bool TryValidateItem(QuarantinedFile item, string directory, out string storedPath, out string metadataPath, out string reason)
    {
        storedPath = string.Empty;
        metadataPath = string.Empty;
        if (!Guid.TryParseExact(item.Id, "N", out _))
        {
            reason = "Некорректный идентификатор записи карантина.";
            return false;
        }
        storedPath = StoredPathFor(directory, item.Id);
        metadataPath = MetadataPathFor(directory, item.Id);
        if (!PathEquals(item.StoredPath, storedPath) || !File.Exists(metadataPath))
        {
            reason = "Запись карантина повреждена или не принадлежит локальному хранилищу.";
            return false;
        }
        if (string.IsNullOrWhiteSpace(item.OriginalPath) || !Path.IsPathRooted(item.OriginalPath))
        {
            reason = "Исходный путь в метаданных некорректен.";
            return false;
        }
        reason = string.Empty;
        return true;
    }

    private static void EnsureSafeSourcePath(string source, string quarantineDirectory)
    {
        var quarantineRoot = Path.GetFullPath(quarantineDirectory);
        EnsureNoReparsePointInParents(quarantineRoot);
        EnsureNoReparsePointInParents(Path.GetDirectoryName(source)!);
        if (IsWithinDirectory(quarantineRoot, source))
            throw new IOException("Файлы из самого карантина нельзя повторно помещать в него.");
        EnsureNotWindowsDirectory(source);
        try
        {
            var runningApp = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(runningApp) && PathEquals(source, Path.GetFullPath(runningApp)))
                throw new IOException("Нельзя помещать исполняемый файл DefenderGuard в собственный карантин.");
        }
        catch (IOException) { throw; }
        catch { }
    }

    private static void EnsureNotWindowsDirectory(string path)
    {
        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windowsDirectory) && IsWithinDirectory(Path.GetFullPath(windowsDirectory), Path.GetFullPath(path)))
            throw new IOException("Файлы из папки Windows защищены от помещения в локальный карантин. Для системных угроз используйте встроенную Историю защиты Windows.");
    }

    private static bool IsWithinDirectory(string root, string path)
    {
        try
        {
            var relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
            return relative == "." || (!Path.IsPathRooted(relative)
                && !relative.Equals("..", StringComparison.Ordinal)
                && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !relative.StartsWith(".." + Path.AltDirectorySeparatorChar, StringComparison.Ordinal));
        }
        catch { return false; }
    }

    private static void EnsureNoReparsePointInParents(string path)
    {
        if (!OperatingSystem.IsWindows()) return;
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Protected operation blocked through reparse-point directory: " + current.FullName);
            current = current.Parent;
        }
    }

    private static string StoredPathFor(string directory, string id) => Path.GetFullPath(Path.Combine(directory, id + ".qtn"));
    private static string MetadataPathFor(string directory, string id) => Path.GetFullPath(Path.Combine(directory, id + ".json"));

    private static void WriteMetadata(QuarantinedFile item, string directory, bool overwrite)
    {
        var metadataPath = MetadataPathFor(directory, item.Id);
        var tempPath = metadataPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(tempPath, JsonSerializer.Serialize(item, JsonOptions), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(tempPath, metadataPath, overwrite);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static bool TryReadLegacyDate(string json, out DateTime date)
    {
        date = default;
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("DetectedAt", out var element)
                && element.TryGetDateTime(out date);
        }
        catch { return false; }
    }

    private static string ComputeSha256(string path)
    {
        using var stream = SafeFileAccess.OpenRegularFileRead(path, BufferSize);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static bool HashMatches(string path, string expectedHash)
    {
        if (string.IsNullOrWhiteSpace(expectedHash)) return false;
        try
        {
            var expected = Convert.FromHexString(expectedHash);
            var actual = Convert.FromHexString(ComputeSha256(path));
            return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
        }
        catch { return false; }
    }

    private static FileAttributes RestoreAttributes(int storedAttributes)
    {
        const FileAttributes allowed = FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System
            | FileAttributes.Archive | FileAttributes.Temporary | FileAttributes.NotContentIndexed | FileAttributes.Offline;
        var attributes = (FileAttributes)storedAttributes & allowed;
        return attributes == 0 ? FileAttributes.Normal : attributes;
    }

    private static string ConflictPath(string originalPath, string id, int attempt)
    {
        var directory = Path.GetDirectoryName(originalPath)!;
        var name = Path.GetFileNameWithoutExtension(originalPath);
        var extension = Path.GetExtension(originalPath);
        var suffix = $"_restored_{DateTime.Now:yyyyMMdd_HHmmss}_{id[..8]}";
        if (attempt > 0) suffix += "_" + attempt;
        return Path.Combine(directory, name + suffix + extension);
    }

    private static bool PathEquals(string left, string right)
    {
        try { return string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}