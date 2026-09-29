using System.Runtime.InteropServices;
using System.Security;

namespace DemoGuard;

internal sealed record CleanupTarget(
    string Id,
    string Category,
    string Description,
    string RootPath,
    long SizeBytes,
    int FileCount,
    string? FilePattern = null);

internal sealed record CleanupDeletionResult(
    string TargetId,
    int DeletedFiles,
    long DeletedBytes,
    int SkippedFiles,
    string? Error);

internal static class CleanupService
{
    private static readonly string UserTemp = Path.GetFullPath(Path.GetTempPath());
    private static readonly string WindowsTemp = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string RoamingAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    public static IReadOnlyList<CleanupTarget> ScanSafeTempTargets()
    {
        var targets = new List<CleanupTarget>();
        AddDirectoryTarget(targets, "user-temp", "Временные файлы пользователя",
            "TMP", UserTemp);
        AddDirectoryTarget(targets, "windows-temp", "Временные файлы Windows",
            "Windows Temp", WindowsTemp);
        AddBrowserCacheTargets(targets);
        AddDirectoryTarget(targets, "thumb-cache", "Кэш миниатюр Windows",
            "Изображения миниатюр", Path.Combine(LocalAppData, "Microsoft", "Windows", "Explorer"),
            "thumbcache_*.db");
        AddDirectoryTarget(targets, "dx-shader-cache", "DirectX Shader Cache",
            "Кэш шейдеров DirectX", Path.Combine(LocalAppData, "D3DSCache"));
        AddRecycleBinTarget(targets);
        return targets;
    }

    public static CleanupDeletionResult DeleteTarget(CleanupTarget target)
    {
        if (target.Id.Equals("recycle-bin", StringComparison.Ordinal))
            return EmptyRecycleBin(target);

        if (!IsAllowedRoot(target.RootPath, target.Id))
            return new CleanupDeletionResult(target.Id, 0, 0, 0,
                "Путь очистки не входит в разрешённый список.");

        var deleted = 0;
        var skipped = 0;
        long deletedBytes = 0;
        string? firstError = null;

        try
        {
            foreach (var file in EnumerateFilesSafe(target.RootPath, target.FilePattern))
            {
                try
                {
                    var info = new FileInfo(file);
                    var length = info.Exists ? info.Length : 0;
                    File.Delete(file);
                    deleted++;
                    deletedBytes += length;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
                {
                    skipped++;
                    firstError ??= ex.Message;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            firstError ??= ex.Message;
        }

        return new CleanupDeletionResult(target.Id, deleted, deletedBytes, skipped, firstError);
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} Б";
        if (bytes < 1024 * 1024) return $"{bytes / 1024d:0.0} КБ";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024d / 1024d:0.0} МБ";
        return $"{bytes / 1024d / 1024d / 1024d:0.00} ГБ";
    }

    private static void AddBrowserCacheTargets(List<CleanupTarget> targets)
    {
        var chromeRoot = Path.Combine(LocalAppData, "Google", "Chrome", "User Data");
        var edgeRoot = Path.Combine(LocalAppData, "Microsoft", "Edge", "User Data");
        AddChromiumProfiles(targets, chromeRoot, "chrome-cache", "Google Chrome");
        AddChromiumProfiles(targets, edgeRoot, "edge-cache", "Microsoft Edge");

        var firefoxRoot = Path.Combine(RoamingAppData, "Mozilla", "Firefox", "Profiles");
        if (!Directory.Exists(firefoxRoot)) return;

        foreach (var profile in SafeDirectories(firefoxRoot))
        {
            var cache = Path.Combine(profile, "cache2");
            AddDirectoryTarget(targets, "firefox-cache", "Mozilla Firefox",
                "Кэш профиля Firefox", cache);
        }
    }

    private static void AddChromiumProfiles(List<CleanupTarget> targets,
        string userDataRoot, string idPrefix, string browserName)
    {
        if (!Directory.Exists(userDataRoot)) return;
        foreach (var profile in SafeDirectories(userDataRoot))
        {
            var profileName = Path.GetFileName(profile);
            if (!profileName.Equals("Default", StringComparison.OrdinalIgnoreCase) &&
                !profileName.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                continue;

            AddDirectoryTarget(targets, idPrefix + "-" + profileName,
                browserName, $"Кэш профиля {profileName}",
                Path.Combine(profile, "Cache"));
            AddDirectoryTarget(targets, idPrefix + "-" + profileName + "-code",
                browserName, $"Code Cache профиля {profileName}",
                Path.Combine(profile, "Code Cache"));
            AddDirectoryTarget(targets, idPrefix + "-" + profileName + "-gpu",
                browserName, $"GPU Cache профиля {profileName}",
                Path.Combine(profile, "GPUCache"));
        }
    }

    private static IEnumerable<string> SafeDirectories(string root)
    {
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = false,
                IgnoreInaccessible = true,
                ReturnSpecialDirectories = false,
                AttributesToSkip = FileAttributes.ReparsePoint
            };
            return Directory.EnumerateDirectories(root, "*", options)
                .Where(path => IsSafeDirectory(root, path))
                .ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    private static void AddDirectoryTarget(List<CleanupTarget> targets, string id,
        string category, string description, string rootPath, string? filePattern = null)
    {
        if (!IsAllowedRoot(rootPath, id) && !IsDiscoverableCacheRoot(rootPath, id, filePattern))
            return;
        if (!Directory.Exists(rootPath)) return;

        long size = 0;
        var count = 0;
        foreach (var file in EnumerateFilesSafe(rootPath, filePattern))
        {
            try
            {
                var info = new FileInfo(file);
                if (!info.Exists) continue;
                size += Math.Max(0, info.Length);
                count++;
            }
            catch { }
        }

        if (count > 0)
            targets.Add(new CleanupTarget(id, category, description, rootPath, size, count, filePattern));
    }

    private static void AddRecycleBinTarget(List<CleanupTarget> targets)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var info = new SHQUERYRBINFO { cbSize = (uint)Marshal.SizeOf<SHQUERYRBINFO>() };
            if (SHQueryRecycleBin(null, ref info) != 0 || info.i64NumItems <= 0) return;
            targets.Add(new CleanupTarget(
                "recycle-bin", "Корзина",
                "Безвозвратное удаление содержимого Корзины",
                "Recycle Bin", Math.Max(0, info.i64Size),
                info.i64NumItems > int.MaxValue ? int.MaxValue : (int)info.i64NumItems));
        }
        catch { }
    }

    private static CleanupDeletionResult EmptyRecycleBin(CleanupTarget target)
    {
        try
        {
            var result = SHEmptyRecycleBin(IntPtr.Zero, null, 0x00000001);
            return result == 0
                ? new CleanupDeletionResult(target.Id, target.FileCount, target.SizeBytes, 0, null)
                : new CleanupDeletionResult(target.Id, 0, 0, 0,
                    $"Windows вернула код 0x{result:X8} при очистке Корзины.");
        }
        catch (Exception ex)
        {
            return new CleanupDeletionResult(target.Id, 0, 0, 0, ex.Message);
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(string rootPath, string? filePattern = null)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            ReturnSpecialDirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        foreach (var file in Directory.EnumerateFiles(rootPath, filePattern ?? "*", options))
        {
            if (IsSafeFilePath(rootPath, file))
                yield return file;
        }
    }

    private static bool IsSafeDirectory(string rootPath, string directoryPath)
    {
        try
        {
            var fullRoot = EnsureTrailingSeparator(Path.GetFullPath(rootPath));
            var fullDirectory = Path.GetFullPath(directoryPath);
            if (!fullDirectory.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase)) return false;
            if ((File.GetAttributes(fullDirectory) & FileAttributes.ReparsePoint) != 0) return false;
            return true;
        }
        catch { return false; }
    }

    private static bool IsSafeFilePath(string rootPath, string filePath)
    {
        try
        {
            var fullRoot = EnsureTrailingSeparator(Path.GetFullPath(rootPath));
            var fullFile = Path.GetFullPath(filePath);
            if (!fullFile.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase)) return false;
            if ((File.GetAttributes(fullFile) & FileAttributes.ReparsePoint) != 0) return false;
            return true;
        }
        catch { return false; }
    }

    private static bool IsAllowedRoot(string rootPath, string id)
    {
        try
        {
            var full = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar);
            if (id.Equals("user-temp", StringComparison.Ordinal))
                return full.Equals(UserTemp.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
            if (id.Equals("windows-temp", StringComparison.Ordinal))
                return full.Equals(Path.GetFullPath(WindowsTemp).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
            if (id.Equals("thumb-cache", StringComparison.Ordinal))
                return full.Equals(Path.Combine(LocalAppData, "Microsoft", "Windows", "Explorer").TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
            if (id.Equals("dx-shader-cache", StringComparison.Ordinal))
                return full.Equals(Path.Combine(LocalAppData, "D3DSCache").TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
        }
        catch { }
        return IsDiscoverableCacheRoot(rootPath, id, null);
    }

    private static bool IsDiscoverableCacheRoot(string rootPath, string id, string? filePattern)
    {
        try
        {
            var full = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar);
            if (id.StartsWith("chrome-cache-", StringComparison.OrdinalIgnoreCase))
                return IsChromiumCachePath(full, Path.Combine(LocalAppData, "Google", "Chrome", "User Data"));
            if (id.StartsWith("edge-cache-", StringComparison.OrdinalIgnoreCase))
                return IsChromiumCachePath(full, Path.Combine(LocalAppData, "Microsoft", "Edge", "User Data"));
            if (id.Equals("firefox-cache", StringComparison.OrdinalIgnoreCase))
                return IsFirefoxCachePath(full);
        }
        catch { }
        return false;
    }

    private static bool IsChromiumCachePath(string path, string userDataRoot)
    {
        var root = EnsureTrailingSeparator(Path.GetFullPath(userDataRoot));
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;
        var relative = Path.GetRelativePath(root, path);
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Length != 2 && parts.Length != 3) return false;
        if (parts.Length == 2)
            return string.Equals(parts[1], "Cache", StringComparison.OrdinalIgnoreCase);
        return (string.Equals(parts[1], "Code Cache", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(parts[1], "GPUCache", StringComparison.OrdinalIgnoreCase))
            && (parts[0].Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                parts[0].StartsWith("Profile ", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsFirefoxCachePath(string path)
    {
        var root = EnsureTrailingSeparator(Path.Combine(RoamingAppData, "Mozilla", "Firefox", "Profiles"));
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;
        var relative = Path.GetRelativePath(root, path);
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return parts.Length == 2 && parts[1].Equals("cache2", StringComparison.OrdinalIgnoreCase);
    }

    private static string EnsureTrailingSeparator(string path)
        => path.EndsWith(Path.DirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;

    [StructLayout(LayoutKind.Sequential)]
    private struct SHQUERYRBINFO
    {
        public uint cbSize;
        public long i64Size;
        public long i64NumItems;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHQueryRecycleBin(string? pszRootPath, ref SHQUERYRBINFO pSHQueryRBInfo);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? pszRootPath, uint dwFlags);
}