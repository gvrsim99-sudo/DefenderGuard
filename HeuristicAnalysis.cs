using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace DemoGuard;

internal enum HeuristicRisk
{
    Low,
    Medium,
    High
}

internal sealed record HeuristicFinding(
    DateTime ObservedAt,
    string Source,
    string Subject,
    string? FilePath,
    int Score,
    HeuristicRisk Risk,
    IReadOnlyList<string> Reasons);

internal sealed record HeuristicBatch(
    string Scope,
    int Examined,
    int Unreadable,
    IReadOnlyList<HeuristicFinding> Findings);

internal static class HeuristicAnalyzer
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".com", ".scr", ".dll", ".sys", ".msi"
    };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".bat", ".cmd", ".wsf"
    };

    private static readonly Regex QuotedWindowsPath = new(@"""(?<path>(?:[A-Za-z]:\\|\\\\)[^""]+)""", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex BareWindowsPath = new(@"(?<path>(?:[A-Za-z]:\\|\\\\)[^\s,""']+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex EncodedCommand = new(@"(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex HiddenWindow = new(@"(?:-windowstyle\s+hidden|-w\s+hidden|-window\s+hidden)", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ExecutionPolicyBypass = new(@"(?:-executionpolicy\s+bypass|-ep\s+bypass)", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DownloadPrimitive = new(@"(?:downloadstring|invoke-webrequest|\biwr\b|start-bitstransfer|bitsadmin|certutil.{0,80}-urlcache|\b(?:curl|wget)\b)", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex DynamicExecution = new(@"(?:invoke-expression|\biex\b|frombase64string)", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ScriptHost = new(@"(?:powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex RemoteUrl = new(@"https?://", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] StartupRegistryKeys =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ];

    public static HeuristicBatch AnalyzeStartup()
    {
        if (!OperatingSystem.IsWindows())
            return new HeuristicBatch("Автозагрузка", 0, 1, Array.Empty<HeuristicFinding>());

        var findings = new List<HeuristicFinding>();
        var examined = 0;
        var unreadable = 0;

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
                    examined++;
                    var finding = AnalyzeFile(path, "Папка автозагрузки", isStartupEntry: true);
                    if (finding is not null) findings.Add(finding);
                }
            }
            catch { unreadable++; }
        }

        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                foreach (var subkeyName in StartupRegistryKeys)
                {
                    try
                    {
                        using var key = baseKey.OpenSubKey(subkeyName, writable: false);
                        if (key is null) continue;
                        foreach (var valueName in key.GetValueNames())
                        {
                            try
                            {
                                var command = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString();
                                if (string.IsNullOrWhiteSpace(command)) continue;
                                examined++;
                                var source = $"{hive}\\{subkeyName}\\{valueName}";
                                var finding = AnalyzeStartupCommand(source, command);
                                if (finding is not null) findings.Add(finding);
                            }
                            catch { unreadable++; }
                        }
                    }
                    catch { unreadable++; }
                }
            }
            catch { unreadable++; }
        }

        return new HeuristicBatch("Автозагрузка", examined, unreadable, Sort(findings));
    }

    public static HeuristicBatch AnalyzeActiveProcesses()
    {
        var findings = new List<HeuristicFinding>();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var examined = 0;
        var unreadable = 0;

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var path = process.MainModule?.FileName;
                    if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                    {
                        unreadable++;
                        continue;
                    }
                    var name = Path.GetFileName(path);
                    if (name.Equals("DefenderGuard.exe", StringComparison.OrdinalIgnoreCase)
                        || name.Equals("MpCmdRun.exe", StringComparison.OrdinalIgnoreCase)) continue;
                    var fullPath = Path.GetFullPath(path);
                    if (!paths.Add(fullPath)) continue;
                    examined++;
                    var finding = AnalyzeFile(fullPath, "Активный процесс: " + process.ProcessName);
                    if (finding is not null) findings.Add(finding);
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException or UnauthorizedAccessException or ArgumentException)
                {
                    unreadable++;
                }
            }
        }

        return new HeuristicBatch("Активные процессы", examined, unreadable, Sort(findings));
    }

    public static HeuristicFinding? AnalyzeProcessStart(string processName, string path)
    {
        var finding = AnalyzeFile(path, "Новый запуск процесса: " + processName);
        return finding;
    }

    public static HeuristicFinding? AnalyzeSelectedFile(string path) => AnalyzeFile(path, "Выбранный файл");

    // Kept public within the internal module to permit deterministic rule tests without touching the registry.
    public static HeuristicFinding? AnalyzeStartupCommand(string source, string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
        var candidatePath = ExtractExistingPath(expanded);
        var accumulator = new FindingAccumulator();
        if (candidatePath is not null)
            AddFileSignals(candidatePath, isStartupEntry: true, accumulator);

        if (EncodedCommand.IsMatch(expanded))
            accumulator.Add("Параметр запуска содержит закодированную команду PowerShell.", 3, "Обфускация");
        if (ExecutionPolicyBypass.IsMatch(expanded))
            accumulator.Add("Параметры обходят Execution Policy PowerShell.", 2, "Настройки выполнения");
        if (HiddenWindow.IsMatch(expanded))
            accumulator.Add("Запрос скрытого окна выполнения.", 2, "Скрытое выполнение");
        if (DownloadPrimitive.IsMatch(expanded) && ScriptHost.IsMatch(expanded))
            accumulator.Add("Сценарный интерпретатор сочетается с командой загрузки из сети.", 3, "Сетевая загрузка");
        if (DynamicExecution.IsMatch(expanded))
            accumulator.Add("Используется динамическое выполнение или декодирование строки.", 2, "Динамическое выполнение");
        if (RemoteUrl.IsMatch(expanded) && ScriptHost.IsMatch(expanded))
            accumulator.Add("Команда сценарного интерпретатора содержит удалённый URL.", 2, "Сетевая команда");

        var subject = candidatePath ?? Truncate(expanded, 220);
        return accumulator.ToFinding(source, subject, candidatePath);
    }

    private static HeuristicFinding? AnalyzeFile(string path, string source, bool isStartupEntry = false)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var fullPath = Path.GetFullPath(path);
        var accumulator = new FindingAccumulator();
        AddFileSignals(fullPath, isStartupEntry, accumulator);
        return accumulator.ToFinding(source, fullPath, fullPath);
    }

    private static void AddFileSignals(string path, bool isStartupEntry, FindingAccumulator accumulator)
    {
        var extension = Path.GetExtension(path);
        var isExecutable = ExecutableExtensions.Contains(extension);
        var isScript = ScriptExtensions.Contains(extension);
        var inWritableArea = IsInWritableUserArea(path);
        var inStartupFolder = IsInStartupFolder(path);

        if (isStartupEntry && !extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase) && (isExecutable || isScript))
            accumulator.Add("Исполняемый или сценарный файл находится непосредственно в стандартной папке автозагрузки.", 2, "Автозагрузка");
        if (inWritableArea && (isExecutable || isScript))
            accumulator.Add("Исполняемый или сценарный файл расположен в области, доступной для записи текущему пользователю.", 2, "Путь файла");
        if (isScript)
            accumulator.Add("В запуске участвует сценарный или командный файл.", 2, "Тип файла");
        if (inStartupFolder && isExecutable)
            accumulator.Add("Исполняемый файл находится в папке Startup.", 2, "Автозагрузка");

        try
        {
            if (!File.Exists(path)) return;
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.Hidden) != 0 && (isExecutable || isScript))
                accumulator.Add("Исполняемый или сценарный файл имеет атрибут Hidden.", 1, "Атрибут файла");
            var age = DateTime.UtcNow - File.GetLastWriteTimeUtc(path);
            if (inWritableArea && (isExecutable || isScript) && age >= TimeSpan.Zero && age <= TimeSpan.FromHours(48))
                accumulator.Add("Файл в пользовательской области недавно изменялся (последние 48 часов).", 1, "Недавнее изменение");
        }
        catch { }
    }

    private static string? ExtractExistingPath(string command)
    {
        var candidates = new List<string>();
        foreach (Match match in QuotedWindowsPath.Matches(command)) candidates.Add(match.Groups["path"].Value);
        foreach (Match match in BareWindowsPath.Matches(command)) candidates.Add(match.Groups["path"].Value.TrimEnd(')', ';', ','));
        foreach (var candidate in candidates)
        {
            try
            {
                var expanded = Environment.ExpandEnvironmentVariables(candidate);
                if (Path.IsPathRooted(expanded) && File.Exists(expanded)) return Path.GetFullPath(expanded);
            }
            catch { }
        }
        return null;
    }

    private static bool IsInWritableUserArea(string path)
    {
        var roots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
        };
        return roots.Where(root => !string.IsNullOrWhiteSpace(root)).Any(root => IsWithin(root, path));
    }

    private static bool IsInStartupFolder(string path)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };
        return roots.Where(root => !string.IsNullOrWhiteSpace(root)).Any(root => IsWithin(root, path));
    }

    private static bool IsWithin(string root, string path)
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

    private static List<HeuristicFinding> Sort(IEnumerable<HeuristicFinding> findings) =>
        findings.OrderByDescending(finding => finding.Score).ThenByDescending(finding => finding.ObservedAt).ToList();

    private static string Truncate(string value, int maximum) => value.Length <= maximum ? value : value[..maximum] + "…";

    private sealed class FindingAccumulator
    {
        private readonly List<string> reasons = [];
        private readonly HashSet<string> categories = new(StringComparer.OrdinalIgnoreCase);
        private int score;

        public void Add(string reason, int points, string category)
        {
            if (!reasons.Contains(reason, StringComparer.Ordinal)) reasons.Add(reason);
            score += points;
            categories.Add(category);
        }

        public HeuristicFinding? ToFinding(string source, string subject, string? filePath)
        {
            if (score == 0) return null;
            var risk = score >= 7 && categories.Count >= 2
                ? HeuristicRisk.High
                : score >= 3
                    ? HeuristicRisk.Medium
                    : HeuristicRisk.Low;
            return new HeuristicFinding(DateTime.Now, source, subject, filePath, score, risk, reasons.ToArray());
        }
    }
}