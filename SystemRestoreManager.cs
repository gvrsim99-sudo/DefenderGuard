using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace DemoGuard;

internal sealed record RestorePointPolicy(bool Enabled);

internal sealed record RestorePointResult(
    bool Success,
    bool Created,
    bool ReusedRecent,
    DateTimeOffset? PointTime,
    string Message);

internal static class RestorePointPolicyStore
{
    private static readonly string DataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DemoGuard");
    private static readonly string PolicyPath = Path.Combine(DataDirectory, "restore-point-policy.json");

    public static RestorePointPolicy Load()
    {
        try
        {
            if (File.Exists(PolicyPath))
                return JsonSerializer.Deserialize<RestorePointPolicy>(File.ReadAllText(PolicyPath),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new RestorePointPolicy(true);
        }
        catch { }
        return new RestorePointPolicy(true);
    }

    public static void Save(bool enabled)
    {
        Directory.CreateDirectory(DataDirectory);
        var temporary = PolicyPath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(new RestorePointPolicy(enabled), new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        File.Move(temporary, PolicyPath, overwrite: true);
    }
}

internal static class SystemRestoreManager
{
    private const string PointDescription = "DefenderGuard before Defender scan";
    private static readonly object Sync = new();
    private static RestorePointResult? cachedSuccess;

    private const string Script = @"
$ErrorActionPreference = 'Stop'
try {
  $cutoff = (Get-Date).AddHours(-24)
  $recent = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue |
    Where-Object { try { $_.ConvertToDateTime($_.CreationTime) -ge $cutoff } catch { $false } } |
    Sort-Object SequenceNumber -Descending |
    Select-Object -First 1)
  if ($recent.Count -gt 0) {
    $point = $recent[0]
    $when = $point.ConvertToDateTime($point.CreationTime).ToString('o')
    $description = ([string]$point.Description) -replace '[\r\n|]', ' '
    Write-Output ('DGRESTORE|REUSED|' + $when + '|' + $description)
    exit 0
  }
  Checkpoint-Computer -Description 'DefenderGuard before Defender scan' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
  $when = (Get-Date).ToString('o')
  Write-Output ('DGRESTORE|CREATED|' + $when + '|DefenderGuard before Defender scan')
  exit 0
}
catch {
  $message = ([string]$_.Exception.Message) -replace '[\r\n|]', ' '
  Write-Output ('DGRESTORE|ERROR||' + $message)
  exit 1
}
";

    public static RestorePointResult EnsureRecentPoint()
    {
        lock (Sync)
        {
            if (cachedSuccess is { Success: true, PointTime: not null } cached
                && DateTimeOffset.Now < cached.PointTime.Value.AddHours(24))
            {
                return cached with
                {
                    Created = false,
                    ReusedRecent = true,
                    Message = $"Повторно используется подтверждённая точка восстановления от {cached.PointTime.Value.LocalDateTime:dd.MM.yyyy HH:mm}."
                };
            }

            if (!OperatingSystem.IsWindows())
                return new RestorePointResult(false, false, false, null, "Создание точки восстановления доступно только в Windows 10/11.");
            try
            {
                if (!DefenderClient.IsAdministrator)
                    return new RestorePointResult(false, false, false, null, "Для создания или проверки точки восстановления нужны права администратора.");
            }
            catch (Exception ex)
            {
                return new RestorePointResult(false, false, false, null, "Не удалось проверить административные права: " + Short(ex.Message));
            }

            var result = InvokePowerShell();
            if (result.Success) cachedSuccess = result;
            return result;
        }
    }

    private static RestorePointResult InvokePowerShell()
    {
        try
        {
            var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var powershell = Path.Combine(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(powershell))
                return new RestorePointResult(false, false, false, null, "Windows PowerShell 5.1 не найден.");

            var encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(Script));
            var startInfo = new ProcessStartInfo
            {
                FileName = powershell,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("-NoLogo");
            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-NonInteractive");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-EncodedCommand");
            startInfo.ArgumentList.Add(encodedScript);

            using var process = new Process { StartInfo = startInfo };
            if (!process.Start())
                return new RestorePointResult(false, false, false, null, "Не удалось запустить Windows PowerShell.");
            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(90_000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return new RestorePointResult(false, false, false, null, "Проверка/создание точки восстановления превысила лимит ожидания 90 секунд.");
            }

            var stdout = stdoutTask.GetAwaiter().GetResult();
            var stderr = stderrTask.GetAwaiter().GetResult();
            var marker = stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .LastOrDefault(line => line.StartsWith("DGRESTORE|", StringComparison.Ordinal));
            if (marker is null)
            {
                var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                return new RestorePointResult(false, false, false, null,
                    "Windows не подтвердил создание/наличие точки восстановления. " + Short(detail));
            }

            var parts = marker.Split('|', 4);
            if (parts.Length < 3 || parts[1].Equals("ERROR", StringComparison.OrdinalIgnoreCase))
            {
                var error = parts.Length == 4 ? parts[3] : marker;
                if (string.IsNullOrWhiteSpace(error)) error = "Windows не сообщил причину.";
                return new RestorePointResult(false, false, false, null, Short(error));
            }

            if (!DateTimeOffset.TryParse(parts[2], CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var pointTime))
                return new RestorePointResult(false, false, false, null, "PowerShell сообщил точку, но время её создания не удалось проверить.");

            var created = parts[1].Equals("CREATED", StringComparison.OrdinalIgnoreCase);
            var reused = parts[1].Equals("REUSED", StringComparison.OrdinalIgnoreCase);
            if (!created && !reused)
                return new RestorePointResult(false, false, false, null, "PowerShell вернул неизвестный статус точки восстановления.");

            var description = parts.Length == 4 ? Short(parts[3]) : PointDescription;
            var message = created
                ? $"Создана точка восстановления Windows: «{description}» ({pointTime.LocalDateTime:dd.MM.yyyy HH:mm})."
                : $"Найдена недавняя точка восстановления Windows: «{description}» ({pointTime.LocalDateTime:dd.MM.yyyy HH:mm}); повторное создание не требуется.";
            return new RestorePointResult(true, created, reused, pointTime, message);
        }
        catch (Exception ex)
        {
            return new RestorePointResult(false, false, false, null, "Ошибка модуля System Restore: " + Short(ex.Message));
        }
    }

    private static string Short(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "Дополнительных сведений нет.";
        var compact = string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return compact.Length <= 500 ? compact : compact[..500] + "…";
    }
}