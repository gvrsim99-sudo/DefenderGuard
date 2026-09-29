using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace DemoGuard;

internal sealed record StorageVolumeInfo(
    string Name,
    string Label,
    string FileSystem,
    string DriveType,
    long TotalBytes,
    long FreeBytes,
    string Status);

internal sealed record PhysicalDiskInfo(
    string Model,
    string MediaType,
    string InterfaceType,
    long SizeBytes,
    string Status,
    string HealthStatus,
    string OperationalStatus,
    string SerialNumber,
    string FirmwareVersion,
    double? TemperatureC,
    long? PowerOnHours,
    double? WearPercent,
    ulong? ReadErrors,
    ulong? WriteErrors);

internal sealed record ComputerInventory(
    string ComputerName,
    string Manufacturer,
    string Model,
    string OperatingSystem,
    string WindowsVersion,
    string Architecture,
    string Cpu,
    string CpuCores,
    string CpuThreads,
    string CpuMaxClock,
    string Memory,
    string Motherboard,
    string Bios,
    string Gpu,
    string NetworkAdapters,
    string Uptime,
    string DotNetRuntime);

internal sealed record SystemInventorySnapshot(
    ComputerInventory Computer,
    IReadOnlyList<StorageVolumeInfo> Volumes,
    IReadOnlyList<PhysicalDiskInfo> PhysicalDisks);

internal sealed record SystemLiveMetrics(
    double CpuUsagePercent,
    double MemoryUsagePercent,
    string MemoryUsed,
    string MemoryTotal,
    double? CpuTemperatureC,
    IReadOnlyList<GpuLiveMetric> Gpus,
    DateTime CapturedAt);

internal sealed record GpuLiveMetric(
    string Name,
    double? UsagePercent,
    double? TemperatureC,
    long? MemoryUsedMb,
    long? MemoryTotalMb);

internal static class SystemInventoryReader
{
    public static SystemInventorySnapshot Read()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Инвентаризация системы доступна только в Windows.");

        var computer = ReadComputer();
        var volumes = ReadVolumes();
        var disks = ReadPhysicalDisks();
        return new SystemInventorySnapshot(computer, volumes, disks);
    }

    public static SystemLiveMetrics ReadLiveMetrics()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Мониторинг ресурсов доступен только в Windows.");

        var cpuUsage = ReadCpuUsage();
        var memory = ReadMemoryUsage();
        var cpuTemperature = ReadCpuTemperature();
        var gpus = ReadGpuLiveMetrics();
        return new SystemLiveMetrics(cpuUsage, memory.UsagePercent, memory.Used, memory.Total, cpuTemperature, gpus, DateTime.Now);
    }

    private static ComputerInventory ReadComputer()
    {
        var system = First("SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem");
        var os = First("SELECT Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime FROM Win32_OperatingSystem");
        var cpu = First("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor");
        var board = First("SELECT Manufacturer, Product, Version FROM Win32_BaseBoard");
        var bios = First("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
        var gpus = Query("SELECT Name, AdapterRAM, DriverVersion FROM Win32_VideoController")
            .Select(item => JoinNonEmpty(GetString(item, "Name"), GetMemory(GetUInt64(item, "AdapterRAM")), Prefix("драйвер ", GetString(item, "DriverVersion"))))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();

        var adapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(item => item.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(item => item.Name + " — " + item.NetworkInterfaceType + " — " + item.OperationalStatus)
            .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var boot = GetDateTime(os, "LastBootUpTime");
        var uptime = boot is null ? "Нет данных" : FormatUptime(DateTime.Now - boot.Value);
        var osCaption = GetString(os, "Caption");
        var osVersion = GetString(os, "Version");
        var build = GetString(os, "BuildNumber");
        var windowsVersion = JoinNonEmpty(osVersion, Prefix("сборка ", build));
        var memory = GetMemory(GetUInt64(system, "TotalPhysicalMemory"));
        var cpuName = GetString(cpu, "Name");
        var cores = GetString(cpu, "NumberOfCores");
        var threads = GetString(cpu, "NumberOfLogicalProcessors");
        var clock = GetString(cpu, "MaxClockSpeed");
        var boardName = JoinNonEmpty(GetString(board, "Manufacturer"), GetString(board, "Product"), Prefix("v", GetString(board, "Version")));
        var biosName = JoinNonEmpty(GetString(bios, "Manufacturer"), GetString(bios, "SMBIOSBIOSVersion"), FormatBiosDate(GetString(bios, "ReleaseDate")));

        return new ComputerInventory(
            Environment.MachineName,
            GetString(system, "Manufacturer"),
            GetString(system, "Model"),
            osCaption,
            windowsVersion,
            GetString(os, "OSArchitecture"),
            cpuName,
            cores,
            threads,
            string.IsNullOrWhiteSpace(clock) ? "Нет данных" : clock + " MHz",
            memory,
            boardName,
            biosName,
            gpus.Length == 0 ? "Нет данных" : string.Join(Environment.NewLine, gpus),
            adapters.Length == 0 ? "Нет данных" : string.Join(Environment.NewLine, adapters),
            uptime,
            RuntimeInformation.FrameworkDescription);
    }

    private static IReadOnlyList<StorageVolumeInfo> ReadVolumes()
    {
        var result = new List<StorageVolumeInfo>();
        foreach (var drive in DriveInfo.GetDrives().OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var total = drive.IsReady ? drive.TotalSize : 0;
                var free = drive.IsReady ? drive.AvailableFreeSpace : 0;
                var status = drive.IsReady ? "Доступен" : "Не готов";
                result.Add(new StorageVolumeInfo(
                    drive.Name,
                    drive.IsReady ? drive.VolumeLabel : "",
                    drive.IsReady ? drive.DriveFormat : "",
                    DriveTypeText(drive.DriveType),
                    total,
                    free,
                    status));
            }
            catch (IOException)
            {
                result.Add(new StorageVolumeInfo(drive.Name, "", "", DriveTypeText(drive.DriveType), 0, 0, "Недоступен"));
            }
            catch (UnauthorizedAccessException)
            {
                result.Add(new StorageVolumeInfo(drive.Name, "", "", DriveTypeText(drive.DriveType), 0, 0, "Нет доступа"));
            }
        }
        return result;
    }

    private static IReadOnlyList<PhysicalDiskInfo> ReadPhysicalDisks()
    {
        var storageDisks = TryReadStorageDisks();
        if (storageDisks.Count > 0) return storageDisks;

        return Query("SELECT Model, MediaType, InterfaceType, Size, Status, SerialNumber, FirmwareRevision FROM Win32_DiskDrive")
            .Select(item =>
            {
                var size = GetUInt64(item, "Size");
                var status = string.IsNullOrWhiteSpace(GetString(item, "Status")) ? "Не указан" : GetString(item, "Status");
                var health = string.Equals(status, "OK", StringComparison.OrdinalIgnoreCase) ? "Healthy" : status;
                return new PhysicalDiskInfo(
                    string.IsNullOrWhiteSpace(GetString(item, "Model")) ? "Неизвестный диск" : GetString(item, "Model"),
                    string.IsNullOrWhiteSpace(GetString(item, "MediaType")) ? "Не указан" : GetString(item, "MediaType"),
                    string.IsNullOrWhiteSpace(GetString(item, "InterfaceType")) ? "Не указан" : GetString(item, "InterfaceType"),
                    size > long.MaxValue ? long.MaxValue : (long)size,
                    status,
                    health,
                    status,
                    GetString(item, "SerialNumber"),
                    GetString(item, "FirmwareRevision"),
                    null,
                    null,
                    null,
                    null,
                    null);
            })
            .OrderBy(item => item.Model, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<PhysicalDiskInfo> TryReadStorageDisks()
    {
        try
        {
            const string script = """
$ErrorActionPreference = 'Stop'
$items = foreach ($d in Get-PhysicalDisk) {
    $c = $null
    try { $c = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { }
    [pscustomobject]@{
        Model = $d.FriendlyName
        MediaType = [string]$d.MediaType
        InterfaceType = [string]$d.BusType
        SizeBytes = [int64]$d.Size
        HealthStatus = [string]$d.HealthStatus
        OperationalStatus = ($d.OperationalStatus -join ', ')
        SerialNumber = [string]$d.SerialNumber
        FirmwareVersion = [string]$d.FirmwareVersion
        TemperatureC = if ($null -ne $c -and $null -ne $c.Temperature) { [double]$c.Temperature } else { $null }
        PowerOnHours = if ($null -ne $c -and $null -ne $c.PowerOnHours) { [int64]$c.PowerOnHours } else { $null }
        WearPercent = if ($null -ne $c -and $null -ne $c.Wear) { [double]$c.Wear } else { $null }
        ReadErrors = if ($null -ne $c -and $null -ne $c.ReadErrorsTotal) { [uint64]$c.ReadErrorsTotal } else { $null }
        WriteErrors = if ($null -ne $c -and $null -ne $c.WriteErrorsTotal) { [uint64]$c.WriteErrorsTotal } else { $null }
    }
}
@($items) | ConvertTo-Json -Compress
""";
            var start = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-Command");
            start.ArgumentList.Add(script);
            using var process = Process.Start(start);
            if (process is null) return Array.Empty<PhysicalDiskInfo>();
            if (!process.WaitForExit(7000))
            {
                try { process.Kill(true); } catch { }
                return Array.Empty<PhysicalDiskInfo>();
            }
            var output = process.StandardOutput.ReadToEnd();
            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output)) return Array.Empty<PhysicalDiskInfo>();
            using var document = JsonDocument.Parse(output);
            var result = new List<PhysicalDiskInfo>();
            foreach (var item in document.RootElement.EnumerateArray())
            {
                var health = JsonString(item, "HealthStatus");
                var operational = JsonString(item, "OperationalStatus");
                var status = string.Equals(health, "Healthy", StringComparison.OrdinalIgnoreCase) && string.Equals(operational, "OK", StringComparison.OrdinalIgnoreCase)
                    ? "Норма"
                    : JoinNonEmpty(health, operational);
                result.Add(new PhysicalDiskInfo(
                    JsonString(item, "Model") is { Length: > 0 } model ? model : "Неизвестный диск",
                    JsonString(item, "MediaType") is { Length: > 0 } media ? media : "Не указан",
                    JsonString(item, "InterfaceType") is { Length: > 0 } bus ? bus : "Не указан",
                    JsonInt64(item, "SizeBytes") ?? 0,
                    string.IsNullOrWhiteSpace(status) ? "Нет данных" : status,
                    string.IsNullOrWhiteSpace(health) ? "Нет данных" : health,
                    string.IsNullOrWhiteSpace(operational) ? "Нет данных" : operational,
                    JsonString(item, "SerialNumber"),
                    JsonString(item, "FirmwareVersion"),
                    JsonDouble(item, "TemperatureC"),
                    JsonInt64(item, "PowerOnHours"),
                    JsonDouble(item, "WearPercent"),
                    JsonUInt64(item, "ReadErrors"),
                    JsonUInt64(item, "WriteErrors")));
            }
            return result.OrderBy(item => item.Model, StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch { return Array.Empty<PhysicalDiskInfo>(); }
    }

    private static double ReadCpuUsage()
    {
        try
        {
            var row = First("SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'");
            return Math.Clamp(double.TryParse(GetString(row, "PercentProcessorTime"), out var value) ? value : 0, 0, 100);
        }
        catch { return 0; }
    }

    private static (double UsagePercent, string Used, string Total) ReadMemoryUsage()
    {
        try
        {
            var row = First("SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
            var totalKb = GetUInt64(row, "TotalVisibleMemorySize");
            var freeKb = GetUInt64(row, "FreePhysicalMemory");
            if (totalKb == 0) return (0, "Нет данных", "Нет данных");
            var usedKb = totalKb > freeKb ? totalKb - freeKb : 0;
            var usage = Math.Clamp((double)usedKb / totalKb * 100, 0, 100);
            return (usage, FormatBytes(usedKb * 1024), FormatBytes(totalKb * 1024));
        }
        catch { return (0, "Нет данных", "Нет данных"); }
    }

    private static double? ReadCpuTemperature()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("root\\WMI", "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
            var values = searcher.Get().Cast<ManagementObject>()
                .Select(item => GetUInt64(item, "CurrentTemperature"))
                .Where(value => value > 2500 && value < 3932)
                .Select(value => value / 10.0 - 273.15)
                .Where(value => value is >= 15 and <= 120)
                .ToArray();
            return values.Length == 0 ? null : values.Average();
        }
        catch { return null; }
    }

    private static IReadOnlyList<GpuLiveMetric> ReadGpuLiveMetrics()
    {
        var nvidia = TryReadNvidiaSmi();
        if (nvidia.Count > 0) return nvidia;

        try
        {
            var usageByName = Query("SELECT Name, UtilizationPercentage FROM Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine")
                .GroupBy(item => GetString(item, "Name").Split(new[] { "_engtype_" }, StringSplitOptions.None)[0], StringComparer.OrdinalIgnoreCase)
                .Select(group => new GpuLiveMetric(
                    group.Key,
                    Math.Clamp(group.Sum(item => double.TryParse(GetString(item, "UtilizationPercentage"), out var value) ? value : 0), 0, 100),
                    null,
                    null,
                    null))
                .Where(item => !string.IsNullOrWhiteSpace(item.Name))
                .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return usageByName;
        }
        catch { return Array.Empty<GpuLiveMetric>(); }
    }

    private static IReadOnlyList<GpuLiveMetric> TryReadNvidiaSmi()
    {
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = "nvidia-smi.exe",
                Arguments = "--query-gpu=name,utilization.gpu,temperature.gpu,memory.used,memory.total --format=csv,noheader,nounits",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var process = Process.Start(start);
            if (process is null) return Array.Empty<GpuLiveMetric>();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(2500);
            if (process.ExitCode != 0) return Array.Empty<GpuLiveMetric>();
            return output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Select(line => line.Split(',', StringSplitOptions.TrimEntries))
                .Where(parts => parts.Length >= 5)
                .Select(parts => new GpuLiveMetric(
                    parts[0],
                    double.TryParse(parts[1], out var usage) ? Math.Clamp(usage, 0, 100) : null,
                    double.TryParse(parts[2], out var temp) && temp >= 0 && temp <= 120 ? temp : null,
                    long.TryParse(parts[3], out var memoryUsed) && memoryUsed >= 0 ? memoryUsed : null,
                    long.TryParse(parts[4], out var memoryTotal) && memoryTotal > 0 ? memoryTotal : null))
                .ToArray();
        }
        catch { return Array.Empty<GpuLiveMetric>(); }
    }

    private static string JsonString(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return "";
        return value.ValueKind == JsonValueKind.String ? value.GetString()?.Trim() ?? "" : value.ToString().Trim();
    }

    private static long? JsonInt64(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        try
        {
            if (value.TryGetInt64(out var number)) return number;
            return long.TryParse(value.ToString(), out number) ? number : null;
        }
        catch { return null; }
    }

    private static ulong? JsonUInt64(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        try
        {
            if (value.TryGetUInt64(out var number)) return number;
            return ulong.TryParse(value.ToString(), out number) ? number : null;
        }
        catch { return null; }
    }

    private static double? JsonDouble(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        try
        {
            if (value.TryGetDouble(out var number) && double.IsFinite(number)) return number;
            return double.TryParse(value.ToString(), out number) && double.IsFinite(number) ? number : null;
        }
        catch { return null; }
    }

    private static ManagementObject? First(string query) => Query(query).FirstOrDefault();

    private static IReadOnlyList<ManagementObject> Query(string query)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(query);
            return searcher.Get().Cast<ManagementObject>().ToArray();
        }
        catch
        {
            return Array.Empty<ManagementObject>();
        }
    }

    private static string GetString(ManagementObject? item, string name)
        => item?[name]?.ToString()?.Trim() ?? "";

    private static ulong GetUInt64(ManagementObject? item, string name)
    {
        try { return item?[name] is null ? 0 : Convert.ToUInt64(item[name]); }
        catch { return 0; }
    }

    private static DateTime? GetDateTime(ManagementObject? item, string name)
    {
        try
        {
            var value = GetString(item, name);
            return string.IsNullOrWhiteSpace(value) ? null : ManagementDateTimeConverter.ToDateTime(value);
        }
        catch { return null; }
    }

    private static string GetMemory(ulong bytes) => bytes == 0 ? "Нет данных" : FormatBytes(bytes);

    internal static string FormatBytes(ulong bytes)
    {
        string[] units = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"];
        decimal value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return value >= 100 ? $"{value:0} {units[unit]}" : $"{value:0.##} {units[unit]}";
    }

    internal static string FormatBytes(long bytes) => bytes <= 0 ? "—" : FormatBytes((ulong)bytes);

    private static string DriveTypeText(DriveType type) => type switch
    {
        DriveType.Fixed => "Локальный диск",
        DriveType.Removable => "Съёмный диск",
        DriveType.Network => "Сетевой диск",
        DriveType.CDRom => "Оптический диск",
        DriveType.Ram => "RAM-диск",
        _ => "Неизвестный тип"
    };

    private static string FormatUptime(TimeSpan uptime)
    {
        if (uptime < TimeSpan.Zero) return "Нет данных";
        if (uptime.TotalDays >= 1) return $"{(int)uptime.TotalDays} д {uptime.Hours} ч {uptime.Minutes} мин";
        return $"{uptime.Hours} ч {uptime.Minutes} мин";
    }

    private static string FormatBiosDate(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        try { return ManagementDateTimeConverter.ToDateTime(value).ToString("dd.MM.yyyy"); }
        catch { return ""; }
    }

    private static string Prefix(string prefix, string value) => string.IsNullOrWhiteSpace(value) ? "" : prefix + value;

    private static string JoinNonEmpty(params string[] values) => string.Join(" · ", values.Where(value => !string.IsNullOrWhiteSpace(value)));
}