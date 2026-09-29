using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace DemoGuard;

internal sealed record StartupInventory(IReadOnlyList<string> FilePaths, int EntryCount, int UnresolvedCount, int ReadErrors);

internal static class WindowsStartupScanner
{
    private static readonly string[] RegistrySubkeys =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ];

    private static readonly Regex CommandPathRegex = new(
        @"(?:""(?<quoted>[^""]+)""|(?<path>(?:[A-Za-z]:\\|\\\\)[^\s,;]+))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly HashSet<string> ScannableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".com", ".dll", ".sys", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi", ".lnk"
    };

    public static StartupInventory Collect()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entryCount = 0;
        var unresolvedCount = 0;
        var readErrors = 0;

        foreach (var folder in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        }.Where(path => !string.IsNullOrWhiteSpace(path)))
        {
            try
            {
                if (!Directory.Exists(folder)) continue;
                foreach (var path in Directory.EnumerateFiles(folder))
                {
                    entryCount++;
                    paths.Add(Path.GetFullPath(path));
                }
            }
            catch
            {
                readErrors++;
            }
        }

        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                foreach (var subkeyName in RegistrySubkeys)
                {
                    try
                    {
                        using var key = baseKey.OpenSubKey(subkeyName, writable: false);
                        if (key is null) continue;
                        foreach (var valueName in key.GetValueNames())
                        {
                            try
                            {
                                var command = key.GetValue(valueName)?.ToString();
                                if (string.IsNullOrWhiteSpace(command)) continue;
                                entryCount++;
                                var discovered = ResolveCommandFiles(command).ToArray();
                                if (discovered.Length == 0) unresolvedCount++;
                                foreach (var path in discovered) paths.Add(Path.GetFullPath(path));
                            }
                            catch
                            {
                                readErrors++;
                            }
                        }
                    }
                    catch
                    {
                        readErrors++;
                    }
                }
            }
            catch
            {
                readErrors++;
            }
        }

        return new StartupInventory(paths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray(), entryCount, unresolvedCount, readErrors);
    }

    public static DefenderCommandResult Scan()
    {
        if (!OperatingSystem.IsWindows()) return new(-1, "Проверка автозагрузки доступна только в Windows.");
        if (!DefenderClient.IsAdministrator) return new(-1, "Для проверки файлов автозагрузки запустите приложение от имени администратора.");

        var inventory = Collect();
        if (inventory.FilePaths.Count == 0)
        {
            var message = inventory.EntryCount == 0
                ? "В стандартных папках Startup и ключах Run/RunOnce записей не найдено. Другие механизмы автозапуска этим сканированием не охватываются."
                : $"Найдено записей автозапуска: {inventory.EntryCount}, но не удалось разрешить их в файлы для проверки. Не удалось прочитать источников: {inventory.ReadErrors}.";
            return new(inventory.EntryCount == 0 ? 0 : -1, message);
        }

        var result = DefenderClient.CustomScan(inventory.FilePaths);
        var summary = $"Стандартные точки автозагрузки: записей {inventory.EntryCount}; файлов для сканирования {inventory.FilePaths.Count}; не разрешено в файл {inventory.UnresolvedCount}; ошибок чтения источников {inventory.ReadErrors}.";
        return result with { Output = summary + Environment.NewLine + result.Output };
    }

    private static IEnumerable<string> ResolveCommandFiles(string command)
    {
        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        var candidates = new List<string>();
        foreach (Match match in CommandPathRegex.Matches(expanded))
        {
            var value = match.Groups["quoted"].Success ? match.Groups["quoted"].Value : match.Groups["path"].Value;
            if (!string.IsNullOrWhiteSpace(value)) candidates.Add(value.Trim().TrimEnd(','));
        }

        var firstToken = expanded.Trim().Split([' ', '\t'], 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim('"');
        if (!string.IsNullOrWhiteSpace(firstToken)) candidates.Insert(0, firstToken);

        var resolved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            var path = ResolveExecutable(candidate);
            if (path is null || !File.Exists(path)) continue;
            if (!ScannableExtensions.Contains(Path.GetExtension(path))) continue;
            resolved.Add(Path.GetFullPath(path));
        }
        return resolved;
    }

    private static string? ResolveExecutable(string candidate)
    {
        var expanded = Environment.ExpandEnvironmentVariables(candidate.Trim().Trim('"'));
        if (File.Exists(expanded)) return expanded;
        if (Path.IsPathRooted(expanded)) return null;

        var pathVariable = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var directory in pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var path = Path.Combine(directory.Trim('"'), expanded);
                if (File.Exists(path)) return path;
            }
            catch { }
        }
        return null;
    }
}

internal sealed record ProcessInventory(IReadOnlyList<string> FilePaths, int ProcessCount, int UnreadableCount);

internal static class ActiveProcessScanner
{
    public static ProcessInventory Collect()
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var processCount = 0;
        var unreadableCount = 0;
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                processCount++;
                try
                {
                    var path = process.MainModule?.FileName;
                    if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                    {
                        unreadableCount++;
                        continue;
                    }
                    var name = Path.GetFileName(path);
                    if (name.Equals("DefenderGuard.exe", StringComparison.OrdinalIgnoreCase) || name.Equals("MpCmdRun.exe", StringComparison.OrdinalIgnoreCase))
                        continue;
                    paths.Add(Path.GetFullPath(path));
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException or UnauthorizedAccessException)
                {
                    unreadableCount++;
                }
            }
        }
        return new ProcessInventory(paths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray(), processCount, unreadableCount);
    }

    public static DefenderCommandResult Scan()
    {
        if (!OperatingSystem.IsWindows()) return new(-1, "Проверка образов активных процессов доступна только в Windows.");
        if (!DefenderClient.IsAdministrator) return new(-1, "Для проверки образов процессов запустите приложение от имени администратора.");

        var inventory = Collect();
        if (inventory.FilePaths.Count == 0)
            return new(-1, $"Не найдено доступных файлов образов процессов. Процессов: {inventory.ProcessCount}; недоступных для чтения: {inventory.UnreadableCount}.");

        var result = DefenderClient.CustomScan(inventory.FilePaths);
        var summary = $"Процессов обнаружено: {inventory.ProcessCount}; уникальных файлов образов передано Defender: {inventory.FilePaths.Count}; недоступных для чтения: {inventory.UnreadableCount}. Проверяются файлы на диске, не память процессов.";
        return result with { Output = summary + Environment.NewLine + result.Output };
    }
}

internal sealed class ProcessMonitorService : IDisposable
{
    private const int MaxPendingScanCount = 100;
    private readonly ManagementEventWatcher watcher = new(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
    private readonly ConcurrentDictionary<string, byte> seenFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<(string ProcessName, string Path)> pending = new();
    private int draining;
    private int stopped;
    private int unreadableEvents;
    private int queueFullNotified;
    private long restorePointRetryAfterUtcTicks;

    public event Action<string, bool>? StatusChanged;
    public event Action<HeuristicFinding>? HeuristicFindingReported;

    public void Start()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("WMI-мониторинг процессов доступен только в Windows.");
        if (!DefenderClient.IsAdministrator) throw new UnauthorizedAccessException("Для чтения путей новых процессов нужны права администратора.");
        watcher.EventArrived += OnEventArrived;
        try
        {
            watcher.Start();
        }
        catch
        {
            watcher.EventArrived -= OnEventArrived;
            throw;
        }
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref stopped, 1) != 0) return;
        try { watcher.Stop(); } catch { }
        while (pending.TryDequeue(out _)) { }
    }

    private void OnEventArrived(object sender, EventArrivedEventArgs e)
    {
        if (Volatile.Read(ref stopped) != 0) return;
        try
        {
            var rawPid = e.NewEvent?["ProcessID"];
            if (rawPid is null) return;
            var pid = Convert.ToInt32(rawPid, System.Globalization.CultureInfo.InvariantCulture);
            var rawParentPid = e.NewEvent?["ParentProcessID"];
            var parentPid = rawParentPid is null
                ? 0
                : Convert.ToInt32(rawParentPid, System.Globalization.CultureInfo.InvariantCulture);
            using var process = Process.GetProcessById(pid);
            var path = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                ReportUnavailablePath();
                return;
            }

            var fileName = Path.GetFileName(path);
            if (fileName.Equals("DefenderGuard.exe", StringComparison.OrdinalIgnoreCase)
                || fileName.Equals("MpCmdRun.exe", StringComparison.OrdinalIgnoreCase))
                return;

            if (parentPid == Environment.ProcessId
                && (fileName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)
                    || fileName.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase)))
                return;

            var info = new FileInfo(path);
            var identity = $"{info.FullName}|{info.Length}|{info.LastWriteTimeUtc.Ticks}";
            if (!seenFiles.TryAdd(identity, 0)) return;

            var name = process.ProcessName;
            try
            {
                var heuristic = HeuristicAnalyzer.AnalyzeProcessStart(name, info.FullName);
                if (heuristic is not null) HeuristicFindingReported?.Invoke(heuristic);
            }
            catch { }

            if (pending.Count >= MaxPendingScanCount)
            {
                if (Interlocked.Exchange(ref queueFullNotified, 1) == 0)
                    Notify($"Очередь мониторинга достигла {MaxPendingScanCount} файлов. Новые изображения временно пропускаются; реальную защиту продолжает обеспечивать Microsoft Defender.", true);
                return;
            }

            pending.Enqueue((name, info.FullName));
            Notify($"Запущен процесс {name}; файл образа поставлен в очередь проверки Defender: {info.FullName}", false);
            StartQueue();
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException or UnauthorizedAccessException or ArgumentException)
        {
            ReportUnavailablePath();
        }
        catch (Exception ex)
        {
            Notify("Ошибка наблюдения за запуском процесса: " + ex.Message, true);
        }
    }

    private void StartQueue()
    {
        if (Interlocked.CompareExchange(ref draining, 1, 0) != 0) return;
        _ = Task.Run(DrainQueueAsync);
    }

    private async Task DrainQueueAsync()
    {
        try
        {
            while (Volatile.Read(ref stopped) == 0 && pending.TryDequeue(out var item))
            {
                if (pending.Count < MaxPendingScanCount / 2) Interlocked.Exchange(ref queueFullNotified, 0);
                if (RestorePointPolicyStore.Load().Enabled)
                {
                    var retryAfter = Volatile.Read(ref restorePointRetryAfterUtcTicks);
                    if (retryAfter != 0 && DateTime.UtcNow.Ticks < retryAfter)
                    {
                        while (pending.TryDequeue(out _)) { }
                        break;
                    }

                    var restorePoint = await Task.Run(SystemRestoreManager.EnsureRecentPoint);
                    if (!restorePoint.Success)
                    {
                        Interlocked.Exchange(ref restorePointRetryAfterUtcTicks, DateTime.UtcNow.AddMinutes(5).Ticks);
                        Notify("Фоновая проверка образа процесса пропущена: точка восстановления недоступна. Очередь очищена; повтор будет предпринят не ранее чем через 5 минут. " + restorePoint.Message, true);
                        while (pending.TryDequeue(out _)) { }
                        break;
                    }
                    Interlocked.Exchange(ref restorePointRetryAfterUtcTicks, 0);
                }
                else
                {
                    Interlocked.Exchange(ref restorePointRetryAfterUtcTicks, 0);
                }

                DefenderCommandResult result;
                try
                {
                    result = await Task.Run(() => DefenderClient.CustomScan(item.Path));
                }
                catch (Exception ex)
                {
                    result = new(-1, ex.Message);
                }

                if (Volatile.Read(ref stopped) != 0) break;
                var message = result.ExitCode == 0
                    ? $"Проверка файла процесса завершена (код 0; откройте Историю защиты для результата): {item.ProcessName} — {item.Path}"
                    : $"Проверка файла процесса требует внимания (код {result.ExitCode}): {item.ProcessName} — {item.Path}. {result.Output}";
                Notify(message, result.ExitCode != 0);
            }
        }
        finally
        {
            Interlocked.Exchange(ref draining, 0);
            if (Volatile.Read(ref stopped) == 0 && !pending.IsEmpty) StartQueue();
        }
    }

    private void Notify(string message, bool warning)
    {
        try { StatusChanged?.Invoke(message, warning); } catch { }
    }

    private void ReportUnavailablePath()
    {
        var count = Interlocked.Increment(ref unreadableEvents);
        if (count == 1 || count % 20 == 0)
            Notify($"Windows не предоставил путь к некоторым защищённым/короткоживущим процессам; пропущено событий: {count}.", true);
    }

    public void Dispose()
    {
        Stop();
        watcher.EventArrived -= OnEventArrived;
        try { watcher.Dispose(); } catch { }
    }
}