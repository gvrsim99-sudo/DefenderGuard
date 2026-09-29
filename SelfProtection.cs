using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace DemoGuard;

internal sealed record SelfProtectionStatus(bool Installed, bool Running, string Message);
internal sealed record SelfProtectionResult(bool Success, string Message);
internal readonly record struct WindowsCommandResult(int ExitCode, string Output);

internal static class SelfProtectionPaths
{
    public const string ServiceName = "DefenderGuardSelfProtection";
    public const string ServiceDisplayName = "DefenderGuard — самозащита";
    public const string UiTaskName = "DefenderGuard_SelfProtection_UI";
    public const string ExecutableName = "DefenderGuard.exe";

    public static string InstallDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DefenderGuard");
    public static string ExecutablePath => Path.Combine(InstallDirectory, ExecutableName);
    public static string DataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DefenderGuardSelfProtection");
    public static string IntegrityFile => Path.Combine(DataDirectory, "integrity.sha256");
    public static string LogFile => Path.Combine(DataDirectory, "self-protection.log");
    public static string SingleInstanceMutexName
    {
        get
        {
            var executable = Environment.ProcessPath ?? ExecutableName;
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(executable)));
            return @"Local\DefenderGuard.UI." + Convert.ToHexString(hash.AsSpan(0, 8));
        }
    }

    public static bool SamePath(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right)) return false;
        try { return string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }
}

internal static class SelfProtectionManager
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(30);
    private const string ServiceStatusScript = "$ErrorActionPreference='Stop'; try { [int](Get-Service -Name '" + SelfProtectionPaths.ServiceName + "').Status } catch { exit 1060 }";

    public static bool IsAdministrator
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    public static bool IsCurrentExecutableProtected => SelfProtectionPaths.SamePath(Environment.ProcessPath, SelfProtectionPaths.ExecutablePath);

    public static SelfProtectionStatus GetStatus()
    {
        if (!OperatingSystem.IsWindows()) return new(false, false, "Самозащита доступна только в Windows.");
        var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        var query = WindowsCommand.Run(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ServiceStatusScript], CommandTimeout);
        if (query.ExitCode != 0)
        {
            if (query.ExitCode == 1060) return new(false, false, "Служба самозащиты не установлена.");
            return new(false, false, "Не удалось проверить службу: " + Short(query.Output));
        }

        if (!int.TryParse(query.Output.Trim(), out var serviceState))
            return new(false, false, "Не удалось распознать статус службы: " + Short(query.Output));
        var running = serviceState == 4;
        var state = serviceState switch
        {
            1 => "установлена, но остановлена",
            2 => "запускается",
            3 => "останавливается",
            4 => "работает",
            7 => "приостановлена",
            _ => "установлена; состояние службы не распознано"
        };
        var pathExists = File.Exists(SelfProtectionPaths.ExecutablePath);
        var detail = pathExists
            ? $"Служба {state}; приложение установлено в {SelfProtectionPaths.InstallDirectory}."
            : $"Служба {state}, но защищённый EXE не найден: {SelfProtectionPaths.ExecutablePath}";
        return new(true, running, detail);
    }

    public static SelfProtectionResult Install()
    {
        if (!OperatingSystem.IsWindows()) return new(false, "Установка службы доступна только в Windows.");
        if (!IsAdministrator) return new(false, "Для установки самозащиты требуются права администратора. Подтвердите запрос UAC.");

        var status = GetStatus();
        if (status.Installed) return new(true, "Служба самозащиты уже зарегистрирована. " + status.Message);

        var sourcePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
            return new(false, "Не удалось определить исполняемый файл DefenderGuard для установки.");

        var installDirectory = SelfProtectionPaths.InstallDirectory;
        var targetPath = SelfProtectionPaths.ExecutablePath;
        var createdDirectory = !Directory.Exists(installDirectory);
        var createdDataDirectory = !Directory.Exists(SelfProtectionPaths.DataDirectory);
        var copiedExecutable = false;
        var taskCreated = false;
        var serviceCreated = false;
        var installAclApplied = false;
        string? stagedPath = null;

        try
        {
            Directory.CreateDirectory(installDirectory);
            Directory.CreateDirectory(SelfProtectionPaths.DataDirectory);

            if (!SelfProtectionPaths.SamePath(sourcePath, targetPath))
            {
                stagedPath = targetPath + ".new-" + Guid.NewGuid().ToString("N");
                File.Copy(sourcePath, stagedPath, overwrite: false);
                var sourceHash = ComputeSha256(sourcePath);
                var stagedHash = ComputeSha256(stagedPath);
                if (!string.Equals(sourceHash, stagedHash, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Проверка SHA-256 установленной копии не прошла; исходный файл не изменён.");
                File.Move(stagedPath, targetPath, overwrite: File.Exists(targetPath));
                stagedPath = null;
                copiedExecutable = true;
            }

            var expectedHash = ComputeSha256(targetPath);
            var dataAcl = ApplyDirectoryAcl(SelfProtectionPaths.DataDirectory, usersReadOnly: true);
            if (dataAcl.ExitCode != 0) throw new InvalidOperationException("Не удалось ограничить доступ к данным самозащиты: " + Short(dataAcl.Output));
            WriteIntegrityFile(expectedHash);
            var manifestOwner = WindowsCommand.Run("icacls.exe", [SelfProtectionPaths.IntegrityFile, "/setowner", "*S-1-5-32-544", "/C", "/Q"], CommandTimeout);
            if (manifestOwner.ExitCode != 0) throw new InvalidOperationException("Не удалось закрепить контрольную сумму за группой администраторов: " + Short(manifestOwner.Output));

            installAclApplied = true;
            var installAcl = ApplyDirectoryAcl(installDirectory, usersReadOnly: false);
            if (installAcl.ExitCode != 0) throw new InvalidOperationException("Не удалось защитить каталог Program Files: " + Short(installAcl.Output));

            var account = WindowsIdentity.GetCurrent().Name;
            if (string.IsNullOrWhiteSpace(account)) throw new InvalidOperationException("Не удалось определить пользователя Windows для задачи входа.");
            var task = WindowsCommand.Run("schtasks.exe", [
                "/Create", "/TN", SelfProtectionPaths.UiTaskName,
                "/SC", "ONLOGON",
                "/TR", $"\"{targetPath}\"",
                "/RU", account, "/IT", "/RL", "LIMITED", "/F"
            ], CommandTimeout);
            if (task.ExitCode != 0) throw new InvalidOperationException("Не удалось создать видимую задачу запуска интерфейса при входе пользователя: " + Short(task.Output));
            taskCreated = true;

            var serviceBinPath = $"\"{targetPath}\" --self-protection-service";
            var create = WindowsCommand.Run("sc.exe", [
                "create", SelfProtectionPaths.ServiceName,
                "binPath=", serviceBinPath,
                "type=", "own", "start=", "auto",
                "DisplayName=", SelfProtectionPaths.ServiceDisplayName,
                "obj=", "LocalSystem"
            ], CommandTimeout);
            if (create.ExitCode != 0) throw new InvalidOperationException("Не удалось зарегистрировать службу Windows: " + Short(create.Output));
            serviceCreated = true;

            var description = WindowsCommand.Run("sc.exe", ["description", SelfProtectionPaths.ServiceName, "Контролирует целостность файлов DefenderGuard и перезапускает его пользовательский интерфейс после неожиданного закрытия."], CommandTimeout);
            if (description.ExitCode != 0) throw new InvalidOperationException("Служба создана, но не удалось установить описание: " + Short(description.Output));

            var recovery = WindowsCommand.Run("sc.exe", [
                "failure", SelfProtectionPaths.ServiceName,
                "reset=", "86400", "actions=", "restart/5000/restart/30000/restart/60000"
            ], CommandTimeout);
            if (recovery.ExitCode != 0) throw new InvalidOperationException("Служба создана, но не удалось настроить её восстановление после сбоя: " + Short(recovery.Output));

            var start = WindowsCommand.Run("sc.exe", ["start", SelfProtectionPaths.ServiceName], CommandTimeout);
            if (start.ExitCode != 0 && !start.Output.Contains("1056", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Служба зарегистрирована, но не запустилась: " + Short(start.Output));

            var deadline = DateTime.UtcNow.AddSeconds(60);
            while (DateTime.UtcNow < deadline)
            {
                if (GetStatus().Running)
                {
                    AppendInstallLog($"Установлена служба и задача входа для {account}; контрольный SHA-256 {expectedHash}.");
                    return new(true, "Самозащита установлена. Служба Windows запущена; EXE и контрольная сумма находятся в защищённых каталогах. Интерфейс автоматически откроется из Program Files.");
                }
                Thread.Sleep(400);
            }
            throw new InvalidOperationException("Служба установлена, но не подтвердила состояние «Работает» за 60 секунд.");
        }
        catch (Exception ex)
        {
            if (serviceCreated)
            {
                var state = WindowsCommand.Run("sc.exe", ["query", SelfProtectionPaths.ServiceName], CommandTimeout);
                if (state.ExitCode == 0 && ReadServiceState(state.Output) != 1)
                {
                    WindowsCommand.Run("sc.exe", ["stop", SelfProtectionPaths.ServiceName], CommandTimeout);
                    var stopDeadline = DateTime.UtcNow.AddSeconds(10);
                    while (DateTime.UtcNow < stopDeadline)
                    {
                        var check = WindowsCommand.Run("sc.exe", ["query", SelfProtectionPaths.ServiceName], CommandTimeout);
                        if (check.ExitCode != 0 || ReadServiceState(check.Output) == 1) break;
                        Thread.Sleep(400);
                    }
                }
                WindowsCommand.Run("sc.exe", ["delete", SelfProtectionPaths.ServiceName], CommandTimeout);
            }
            if (taskCreated) DeleteTask();
            if (stagedPath is not null) TryDeleteFile(stagedPath);
            TryDeleteFile(SelfProtectionPaths.IntegrityFile);
            if (createdDataDirectory)
            {
                WindowsCommand.Run("icacls.exe", [SelfProtectionPaths.DataDirectory, "/reset", "/T", "/C", "/Q"], CommandTimeout);
                try { Directory.Delete(SelfProtectionPaths.DataDirectory, recursive: true); } catch { }
            }
            if (installAclApplied)
                WindowsCommand.Run("icacls.exe", [installDirectory, "/reset", "/T", "/C", "/Q"], CommandTimeout);
            if (createdDirectory)
            {
                if (copiedExecutable) TryDeleteFile(targetPath);
                try { Directory.Delete(installDirectory, recursive: true); } catch { }
            }
            return new(false, "Самозащита не установлена. " + ex.Message + "\n\nЕсли Windows уже создала службу или задачу, проверьте раздел «Службы» и Планировщик заданий; приложение не скрывает эти записи.");
        }
    }

    public static SelfProtectionResult Disable()
    {
        if (!OperatingSystem.IsWindows()) return new(false, "Самозащита доступна только в Windows.");
        if (!IsAdministrator) return new(false, "Для отключения службы и её задачи требуются права администратора. Подтвердите запрос UAC.");

        var service = WindowsCommand.Run("sc.exe", ["query", SelfProtectionPaths.ServiceName], CommandTimeout);
        var serviceExists = service.ExitCode == 0;
        if (serviceExists)
        {
            var initialState = ReadServiceState(service.Output);
            if (initialState != 1)
            {
                var stop = WindowsCommand.Run("sc.exe", ["stop", SelfProtectionPaths.ServiceName], CommandTimeout);
                if (stop.ExitCode != 0 && !stop.Output.Contains("1062", StringComparison.OrdinalIgnoreCase))
                    return new(false, "Не удалось остановить службу; задача и ACL оставлены без изменений. " + Short(stop.Output));

                var deadline = DateTime.UtcNow.AddSeconds(20);
                while (DateTime.UtcNow < deadline)
                {
                    var check = WindowsCommand.Run("sc.exe", ["query", SelfProtectionPaths.ServiceName], CommandTimeout);
                    if (check.ExitCode != 0 || ReadServiceState(check.Output) == 1) break;
                    Thread.Sleep(400);
                }
                var final = WindowsCommand.Run("sc.exe", ["query", SelfProtectionPaths.ServiceName], CommandTimeout);
                if (final.ExitCode == 0 && ReadServiceState(final.Output) != 1)
                    return new(false, "Служба не остановилась за 20 секунд; файлы и задача не изменены.");
            }

            var deleteService = WindowsCommand.Run("sc.exe", ["delete", SelfProtectionPaths.ServiceName], CommandTimeout);
            if (deleteService.ExitCode != 0 && !deleteService.Output.Contains("1060", StringComparison.OrdinalIgnoreCase))
                return new(false, "Служба остановлена, но не удалена: " + Short(deleteService.Output));
        }

        var taskQuery = WindowsCommand.Run("schtasks.exe", ["/Query", "/TN", SelfProtectionPaths.UiTaskName], CommandTimeout);
        if (taskQuery.ExitCode == 0)
        {
            var taskDelete = WindowsCommand.Run("schtasks.exe", ["/Delete", "/TN", SelfProtectionPaths.UiTaskName, "/F"], CommandTimeout);
            if (taskDelete.ExitCode != 0) return new(false, "Служба остановлена, но задачу входа удалить не удалось: " + Short(taskDelete.Output));
        }
        else if (!LooksMissingTask(taskQuery.Output))
        {
            return new(false, "Не удалось проверить задачу входа; ACL не изменены: " + Short(taskQuery.Output));
        }

        if (Directory.Exists(SelfProtectionPaths.InstallDirectory))
        {
            var reset = WindowsCommand.Run("icacls.exe", [SelfProtectionPaths.InstallDirectory, "/reset", "/T", "/C", "/Q"], CommandTimeout);
            if (reset.ExitCode != 0) return new(false, "Служба и задача отключены, но сброс ACL каталога не завершён: " + Short(reset.Output));
        }
        TryDeleteFile(SelfProtectionPaths.IntegrityFile);
        AppendInstallLog("Самозащита отключена пользователем через интерфейс DefenderGuard.");
        return new(true, "Служба самозащиты и задача автоматического запуска удалены. Каталог приложения оставлен в Program Files; его можно удалить отдельно с правами администратора.");
    }

    internal static WindowsCommandResult RunUiTask() => WindowsCommand.Run("schtasks.exe", ["/Run", "/TN", SelfProtectionPaths.UiTaskName], TimeSpan.FromSeconds(15));

    internal static WindowsCommandResult DisableUiTask() => WindowsCommand.Run("schtasks.exe", ["/Change", "/TN", SelfProtectionPaths.UiTaskName, "/Disable"], CommandTimeout);

    internal static WindowsCommandResult EnableUiTask() => WindowsCommand.Run("schtasks.exe", ["/Change", "/TN", SelfProtectionPaths.UiTaskName, "/Enable"], CommandTimeout);

    private static WindowsCommandResult ApplyDirectoryAcl(string directory, bool usersReadOnly)
    {
        var userPermissions = usersReadOnly ? "R" : "RX";
        var reset = WindowsCommand.Run("icacls.exe", [directory, "/reset", "/T", "/C", "/Q"], CommandTimeout);
        if (reset.ExitCode != 0) return reset;
        var grant = WindowsCommand.Run("icacls.exe", [
            directory, "/grant:r",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-32-544:(OI)(CI)(F)",
            $"*S-1-5-32-545:(OI)(CI)({userPermissions})",
            "/T", "/C", "/Q"
        ], CommandTimeout);
        if (grant.ExitCode != 0) return grant;
        return WindowsCommand.Run("icacls.exe", [directory, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"], CommandTimeout);
    }

    private static void WriteIntegrityFile(string hash)
    {
        var staging = SelfProtectionPaths.IntegrityFile + ".new";
        File.WriteAllText(staging, hash + Environment.NewLine, Encoding.ASCII);
        File.Move(staging, SelfProtectionPaths.IntegrityFile, overwrite: true);
    }

    private static int ReadServiceState(string output)
    {
        var stateLine = output.Split('\n').FirstOrDefault(line =>
            line.Contains("STATE", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("СОСТОЯНИ", StringComparison.OrdinalIgnoreCase));
        if (stateLine is null) return -1;
        var match = Regex.Match(stateLine, @":\s*(\d+)");
        return match.Success && int.TryParse(match.Groups[1].Value, out var state) ? state : -1;
    }

    private static bool IsSha256(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string ComputeSha256(string path)
    {
        using var stream = SafeFileAccess.OpenRegularFileRead(path, 1024 * 1024);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void AppendInstallLog(string message)
    {
        try
        {
            Directory.CreateDirectory(SelfProtectionPaths.DataDirectory);
            if (File.Exists(SelfProtectionPaths.LogFile) && new FileInfo(SelfProtectionPaths.LogFile).Length > 1_048_576)
                File.Move(SelfProtectionPaths.LogFile, SelfProtectionPaths.LogFile + ".1", overwrite: true);
            File.AppendAllText(SelfProtectionPaths.LogFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\t{message}{Environment.NewLine}", Encoding.UTF8);
        }
        catch { }
    }

    private static bool DeleteTask()
    {
        var query = WindowsCommand.Run("schtasks.exe", ["/Query", "/TN", SelfProtectionPaths.UiTaskName], CommandTimeout);
        if (query.ExitCode != 0) return LooksMissingTask(query.Output);
        return WindowsCommand.Run("schtasks.exe", ["/Delete", "/TN", SelfProtectionPaths.UiTaskName, "/F"], CommandTimeout).ExitCode == 0;
    }

    private static bool LooksMissingService(string output) =>
        output.Contains("1060", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("does not exist", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("не существует", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("не установлена", StringComparison.OrdinalIgnoreCase);

    private static bool LooksMissingTask(string output) =>
        output.Contains("does not exist", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("cannot find", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("не удается найти", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("не удаётся найти", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("не найден", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("не существует", StringComparison.OrdinalIgnoreCase);

    private static string Short(string text)
    {
        var compact = string.Join(" ", text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return compact.Length <= 700 ? compact : compact[..700] + "…";
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}

internal static class WindowsCommand
{
    public static WindowsCommandResult Run(string command, IReadOnlyList<string> arguments, TimeSpan timeout)
    {
        if (!OperatingSystem.IsWindows()) return new(-1, "Команда доступна только в Windows.");
        try
        {
            var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var executable = Path.Combine(systemDirectory, command);
            var start = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var argument in arguments) start.ArgumentList.Add(argument);
            using var process = Process.Start(start);
            if (process is null) return new(-1, "Не удалось запустить системную команду " + command + ".");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit((int)timeout.TotalMilliseconds))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return new(-1, "Ожидание системной команды истекло.");
            }
            Task.WaitAll(stdout, stderr);
            return new(process.ExitCode, (stdout.Result + Environment.NewLine + stderr.Result).Trim());
        }
        catch (Exception ex) { return new(-1, ex.Message); }
    }
}

internal static class SelfProtectionServiceHost
{
    public static void Run()
    {
        if (!OperatingSystem.IsWindows()) return;
        Host.CreateDefaultBuilder([])
            .UseWindowsService(options => options.ServiceName = SelfProtectionPaths.ServiceName)
            .ConfigureServices(services => services.AddHostedService<SelfProtectionWorker>())
            .Build()
            .Run();
    }
}

internal sealed class SelfProtectionWorker : BackgroundService
{
    private static readonly TimeSpan WatchInterval = TimeSpan.FromSeconds(12);
    private static readonly TimeSpan RestartCooldown = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan IntegrityInterval = TimeSpan.FromMinutes(10);
    private readonly object logGate = new();
    private string? expectedHash;
    private string? lastIntegrityState;
    private volatile bool integrityHealthy;
    private int integrityCheckQueued;
    private bool uiTaskDisabledForIntegrity;
    private DateTime lastRestartAttempt = DateTime.MinValue;
    private DateTime lastRestartFailureLog = DateTime.MinValue;
    private DateTime lastRestartSuccessLog = DateTime.MinValue;
    private DateTime lastTaskToggleAttempt = DateTime.MinValue;
    private FileSystemWatcher? watcher;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            expectedHash = File.Exists(SelfProtectionPaths.IntegrityFile)
                ? File.ReadAllText(SelfProtectionPaths.IntegrityFile).Trim()
                : null;
            if (!IsSha256(expectedHash))
            {
                integrityHealthy = false;
                RecordIntegrityState("Манифест SHA-256 отсутствует или повреждён; служба не запускает UI до переустановки.");
            }
            else
            {
                integrityHealthy = await CheckIntegrityAsync(stoppingToken);
            }

            StartWatcher();
            if (integrityHealthy)
            {
                var enableTask = await Task.Run(SelfProtectionManager.EnableUiTask, stoppingToken);
                if (enableTask.ExitCode == 0) WriteLog("Задача интерфейса проверена и включена при запуске службы.");
                else WriteLog("Не удалось проверить/включить задачу интерфейса при запуске службы: " + Short(enableTask.Output));
            }
            var lastPeriodicIntegrityCheck = DateTime.UtcNow;
            while (!stoppingToken.IsCancellationRequested)
            {
                if (!integrityHealthy)
                {
                    if (!uiTaskDisabledForIntegrity && DateTime.UtcNow - lastTaskToggleAttempt >= TimeSpan.FromSeconds(30))
                    {
                        lastTaskToggleAttempt = DateTime.UtcNow;
                        var disableTask = await Task.Run(SelfProtectionManager.DisableUiTask, stoppingToken);
                        if (disableTask.ExitCode == 0)
                        {
                            uiTaskDisabledForIntegrity = true;
                            WriteLog("Отключена задача UI: контрольная сумма EXE не совпадает с манифестом.");
                        }
                        else if (DateTime.UtcNow - lastRestartFailureLog >= TimeSpan.FromMinutes(10))
                        {
                            lastRestartFailureLog = DateTime.UtcNow;
                            WriteLog("Не удалось отключить задачу UI при несоответствии целостности: " + Short(disableTask.Output));
                        }
                    }
                }
                else
                {
                    if (uiTaskDisabledForIntegrity && DateTime.UtcNow - lastTaskToggleAttempt >= TimeSpan.FromSeconds(30))
                    {
                        lastTaskToggleAttempt = DateTime.UtcNow;
                        var enableTask = await Task.Run(SelfProtectionManager.EnableUiTask, stoppingToken);
                        if (enableTask.ExitCode == 0)
                        {
                            uiTaskDisabledForIntegrity = false;
                            WriteLog("Задача запуска интерфейса снова включена: SHA-256 EXE совпадает с манифестом.");
                        }
                    }

                    if (!IsProtectedUiRunning() && DateTime.UtcNow - lastRestartAttempt >= RestartCooldown)
                    {
                        lastRestartAttempt = DateTime.UtcNow;
                        var result = await Task.Run(SelfProtectionManager.RunUiTask, stoppingToken);
                        if (result.ExitCode == 0 && DateTime.UtcNow - lastRestartSuccessLog >= TimeSpan.FromMinutes(5))
                        {
                            lastRestartSuccessLog = DateTime.UtcNow;
                            WriteLog("Пользовательский интерфейс был закрыт; служба запросила его повторный запуск через Планировщик заданий.");
                        }
                        else if (DateTime.UtcNow - lastRestartFailureLog >= TimeSpan.FromMinutes(10))
                        {
                            lastRestartFailureLog = DateTime.UtcNow;
                            WriteLog("Не удалось запустить пользовательский интерфейс. Возможно, пользователь не вошёл в Windows. " + Short(result.Output));
                        }
                    }
                }

                if (DateTime.UtcNow - lastPeriodicIntegrityCheck >= IntegrityInterval)
                {
                    lastPeriodicIntegrityCheck = DateTime.UtcNow;
                    await CheckIntegrityAsync(stoppingToken);
                }
                await Task.Delay(WatchInterval, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex) { WriteLog("Ошибка фоновой службы: " + ex.Message); throw; }
        finally
        {
            watcher?.Dispose();
            watcher = null;
        }
    }

    private void StartWatcher()
    {
        try
        {
            watcher = new FileSystemWatcher(SelfProtectionPaths.InstallDirectory, SelfProtectionPaths.ExecutableName)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                IncludeSubdirectories = false,
                EnableRaisingEvents = false
            };
            watcher.Changed += OnImageChanged;
            watcher.Created += OnImageChanged;
            watcher.Deleted += OnImageChanged;
            watcher.Renamed += OnImageRenamed;
            watcher.Error += (_, e) => WriteLog("Не удалось продолжить наблюдение за каталогом приложения: " + e.GetException().Message);
            watcher.EnableRaisingEvents = true;
        }
        catch (Exception ex) { WriteLog("Не удалось включить наблюдение за файлом приложения: " + ex.Message); }
    }

    private void OnImageChanged(object sender, FileSystemEventArgs e) => QueueIntegrityCheck();
    private void OnImageRenamed(object sender, RenamedEventArgs e) => QueueIntegrityCheck();

    private void QueueIntegrityCheck()
    {
        if (Interlocked.Exchange(ref integrityCheckQueued, 1) != 0) return;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(500);
                await CheckIntegrityAsync(CancellationToken.None);
            }
            catch (Exception ex) { WriteLog("Ошибка повторной проверки целостности: " + ex.Message); }
            finally { Interlocked.Exchange(ref integrityCheckQueued, 0); }
        });
    }

    private async Task<bool> CheckIntegrityAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(expectedHash) || !File.Exists(SelfProtectionPaths.ExecutablePath))
        {
            integrityHealthy = false;
            RecordIntegrityState("Файл DefenderGuard.exe отсутствует или контрольная сумма недоступна; автоматическая подмена не выполняется.");
            return false;
        }

        try
        {
            string actualHash;
            await using (var stream = SafeFileAccess.OpenRegularFileRead(SelfProtectionPaths.ExecutablePath, 1024 * 1024))
            {
                var hash = await SHA256.HashDataAsync(stream, cancellationToken);
                actualHash = Convert.ToHexString(hash);
            }
            var matches = string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
            integrityHealthy = matches;
            RecordIntegrityState(matches
                ? "Целостность DefenderGuard.exe подтверждена по SHA-256."
                : "Обнаружено несоответствие SHA-256 EXE; задача автозапуска UI отключена. Проверьте Историю защиты и переустановите приложение вручную.");
            return matches;
        }
        catch (Exception ex)
        {
            integrityHealthy = false;
            RecordIntegrityState("Не удалось проверить целостность EXE: " + ex.Message);
            return false;
        }
    }

    private void RecordIntegrityState(string message)
    {
        var key = integrityHealthy + "|" + message;
        if (string.Equals(lastIntegrityState, key, StringComparison.Ordinal)) return;
        lastIntegrityState = key;
        WriteLog(message);
    }

    private static bool IsSha256(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length == 64 && value.All(Uri.IsHexDigit);

    private static bool IsProtectedUiRunning()
    {
        foreach (var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(SelfProtectionPaths.ExecutableName)))
        {
            using (process)
            {
                try
                {
                    if (process.SessionId <= 0) continue;
                    var executable = process.MainModule?.FileName;
                    if (SelfProtectionPaths.SamePath(executable, SelfProtectionPaths.ExecutablePath)) return true;
                }
                catch { }
            }
        }
        return false;
    }

    private void WriteLog(string message)
    {
        try
        {
            lock (logGate)
            {
                if (File.Exists(SelfProtectionPaths.LogFile) && new FileInfo(SelfProtectionPaths.LogFile).Length > 1_048_576)
                    File.Move(SelfProtectionPaths.LogFile, SelfProtectionPaths.LogFile + ".1", overwrite: true);
                File.AppendAllText(SelfProtectionPaths.LogFile, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\t{message}{Environment.NewLine}", Encoding.UTF8);
            }
        }
        catch { }
    }

    private static string Short(string text)
    {
        var compact = string.Join(" ", text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return compact.Length <= 500 ? compact : compact[..500] + "…";
    }
}