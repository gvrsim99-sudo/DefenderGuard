using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace DemoGuard;

internal sealed record TcpConnectionSnapshot(
    int ProcessId,
    string ProcessName,
    string? ImagePath,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    int RiskScore,
    string RiskLevel,
    string RiskReasons);

internal sealed record TcpConnectionRaw(
    int ProcessId,
    string ProcessName,
    string? ImagePath,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State);

internal sealed record UdpEndpointRaw(int ProcessId, string ProcessName, string? ImagePath, string LocalAddress, int LocalPort);

internal sealed record UdpEndpointSnapshot(int ProcessId, string ProcessName, string? ImagePath, string LocalAddress, int LocalPort, int RiskScore, string RiskLevel, string RiskReasons);

internal sealed record DnsQuerySnapshot(DateTime TimeCreated, string QueryName, string QueryType, string QueryResults, string QueryStatus, int? ClientProcessId, string ProcessName, string? ImagePath, int RiskScore, string RiskLevel, string RiskReasons);

internal static class NetworkMetadataAnalyzer
{
    private static readonly HashSet<int> UnusualUdpPorts = [1337, 4444, 5555, 6666, 6667, 31337];
    private static readonly HashSet<int> CommonDnsTypes = [1, 2, 5, 6, 12, 15, 16, 28, 33, 43, 46, 47, 48, 52, 64, 65];

    public static IReadOnlyList<UdpEndpointSnapshot> AnalyzeUdp(IEnumerable<UdpEndpointRaw> source)
    {
        return source.Where(row => row.ProcessId >= 0 && row.LocalPort is >= 0 and <= 65535)
            .Select(row =>
            {
                var reasons = new List<string>();
                var score = 0;
                if (string.IsNullOrWhiteSpace(row.ImagePath)) { score++; reasons.Add("Путь процесса недоступен; PID/endpoint видны, но владелец не подтверждён."); }
                else if (NetworkTrafficAnalyzer.IsUserWritableImage(row.ImagePath)) { score += 2; reasons.Add("UDP-сокет принадлежит образу из пользовательской или временной папки."); }
                if (UnusualUdpPorts.Contains(row.LocalPort)) { score += 2; reasons.Add($"Локальный UDP-порт {row.LocalPort} нетипичен и иногда встречается в тестовых/административных инструментах."); }
                var level = RiskLevel(score);
                return new UdpEndpointSnapshot(row.ProcessId, row.ProcessName, row.ImagePath, row.LocalAddress, row.LocalPort, score, level,
                    reasons.Count == 0 ? "Это UDP endpoint (привязка сокета), не запись удалённого peer или содержимого пакетов." : string.Join(" ", reasons) + " Endpoint сам по себе не подтверждает угрозу.");
            })
            .OrderByDescending(row => row.RiskScore).ThenBy(row => row.ProcessName, StringComparer.OrdinalIgnoreCase).ThenBy(row => row.LocalPort)
            .ToArray();
    }

    public static DnsQuerySnapshot AnalyzeDns(DateTime timeCreated, string queryName, string queryType, string queryResults, string queryStatus, int? clientProcessId, string processName = "(не определён)", string? imagePath = null)
    {
        var reasons = new List<string>();
        var score = 0;
        var normalized = queryName.Trim().TrimEnd('.');
        var labels = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var longest = labels.Select(label => label.Length).DefaultIfEmpty(0).Max();
        if (longest >= 50) { score += 2; reasons.Add($"Очень длинная DNS-метка ({longest} символов); длинные имена также применяются легитимными сервисами."); }
        else if (longest >= 35) { score++; reasons.Add($"DNS-метка необычно длинная ({longest} символов); это слабый сигнал."); }
        if (labels.Any(label => label.Length >= 20 && ShannonEntropy(label) >= 3.8)) { score++; reasons.Add("Есть длинная метка с высокой вариативностью символов; это может встречаться в динамических доменах/CDN и не доказывает туннелирование."); }
        if (TryParseDnsType(queryType, out var type) && !CommonDnsTypes.Contains(type))
        {
            score += type is 249 or 250 or 252 or 255 ? 2 : 1;
            reasons.Add($"Необычный тип DNS-запроса {queryType}; проверьте контекст приложения и сети.");
        }
        else if (!TryParseDnsType(queryType, out _) && IsUnusualDnsTypeName(queryType))
        {
            score += 2;
            reasons.Add($"Редкий тип DNS-запроса {queryType}; проверьте контекст приложения и сети.");
        }
        else if (!TryParseDnsType(queryType, out _) && !IsKnownDnsTypeName(queryType))
        {
            score++;
            reasons.Add($"Не распознан тип DNS-запроса «{queryType}»; проверьте формат события и контекст.");
        }
        if (string.IsNullOrWhiteSpace(queryName)) { score++; reasons.Add("Имя запроса пустое или отсутствует в событии."); }
        var level = RiskLevel(score);
        return new DnsQuerySnapshot(timeCreated, queryName, queryType, queryResults, queryStatus, clientProcessId, processName, imagePath, score, level,
            reasons.Count == 0 ? "Слабые эвристические признаки не обнаружены. Это не анализ DNS-пакетов и не подтверждение безопасности." : string.Join(" ", reasons) + " Это только приоритет для ручной проверки, не вердикт.");
    }

    private static double ShannonEntropy(string text)
    {
        if (text.Length == 0) return 0;
        return text.GroupBy(ch => ch).Sum(group => { var p = (double)group.Count() / text.Length; return -p * Math.Log2(p); });
    }

    private static bool TryParseDnsType(string value, out int type)
    {
        var token = value.Trim();
        if (token.StartsWith("TYPE", StringComparison.OrdinalIgnoreCase)) token = token[4..];
        return int.TryParse(token, out type);
    }

    private static bool IsKnownDnsTypeName(string value) => value.Trim().ToUpperInvariant() is
        "A" or "AAAA" or "PTR" or "CNAME" or "MX" or "NS" or "TXT" or "SRV" or "SOA" or "HTTPS" or "SVCB" or "CAA" or "DS" or "DNSKEY" or "RRSIG" or "NSEC" or "NSEC3" or "NAPTR" or "TLSA" or "SSHFP" or "ANY" or "TKEY" or "TSIG" or "AXFR";

    private static bool IsUnusualDnsTypeName(string value) => value.Trim().ToUpperInvariant() is "ANY" or "TKEY" or "TSIG" or "AXFR";

    private static string RiskLevel(int score) => score switch { >= 4 => "Повышенный сигнал", >= 2 => "Требует внимания", 1 => "Слабый сигнал", _ => "Явный сигнал не найден" };
}

internal static class NetworkUdpReader
{
    private const string SnapshotScript = @"
$ErrorActionPreference = 'Stop'
$processes = @{}
Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ExecutablePath -ErrorAction SilentlyContinue | ForEach-Object {
    $processes[[int]$_.ProcessId] = [pscustomobject]@{ Name = [string]$_.Name; Path = [string]$_.ExecutablePath }
}
$rows = @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
    $id = [int]$_.OwningProcess
    $name = ""PID $id""
    $path = $null
    if ($processes.ContainsKey($id)) {
        if (-not [string]::IsNullOrWhiteSpace($processes[$id].Name)) { $name = $processes[$id].Name }
        $path = $processes[$id].Path
    }
    [pscustomobject]@{ ProcessId = $id; ProcessName = $name; ImagePath = $path; LocalAddress = [string]$_.LocalAddress; LocalPort = [int]$_.LocalPort }
})
$json = ConvertTo-Json -InputObject $rows -Depth 4 -Compress
[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
";

    public static IReadOnlyList<UdpEndpointSnapshot> Read()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Снимок UDP endpoints доступен только в Windows.");
        var output = NetworkPowerShell.RunJson(SnapshotScript, TimeSpan.FromSeconds(45));
        var raw = JsonSerializer.Deserialize<List<UdpEndpointRaw>>(output, NetworkConnectionReader.JsonOptions()) ?? [];
        return NetworkMetadataAnalyzer.AnalyzeUdp(raw);
    }
}

internal sealed class DnsMonitorService : IDisposable
{
    public const string ChannelName = "Microsoft-Windows-DNS-Client/Operational";
    private readonly object sync = new();
    private EventLogWatcher? watcher;
    private bool disposed;
    public event Action<DnsQuerySnapshot>? QueryReceived;
    public event Action<string>? StatusChanged;
    public string Status { get; private set; } = "Мониторинг выключен.";

    public bool Start()
    {
        lock (sync)
        {
            if (disposed) throw new ObjectDisposedException(nameof(DnsMonitorService));
            if (watcher is not null) return true;
            if (!OperatingSystem.IsWindows()) return SetStatus("DNS-журнал доступен только в Windows.");
            try
            {
                using (var configuration = new EventLogConfiguration(ChannelName))
                    if (!configuration.IsEnabled) return SetStatus($"Журнал {ChannelName} отключён. DefenderGuard не менял его настройки.");
                var query = new EventLogQuery(ChannelName, PathType.LogName, "*[System[(EventID=3008)]]") { TolerateQueryErrors = false };
                watcher = new EventLogWatcher(query, null, readExistingEvents: false);
                watcher.EventRecordWritten += OnEventRecordWritten;
                watcher.Enabled = true;
                SetStatus("DNS-мониторинг включён: отображаются новые события 3008, без чтения истории.");
                return true;
            }
            catch (Exception ex)
            {
                watcher?.Dispose(); watcher = null;
                return SetStatus($"Не удалось подписаться на DNS-журнал: {ex.Message}");
            }
        }
    }

    public void Stop()
    {
        lock (sync)
        {
            if (watcher is not null)
            {
                watcher.EventRecordWritten -= OnEventRecordWritten;
                watcher.Enabled = false;
                watcher.Dispose();
                watcher = null;
            }
            if (!disposed) SetStatus("Мониторинг выключен.");
        }
    }

    private bool SetStatus(string value)
    {
        Status = value;
        StatusChanged?.Invoke(value);
        return value.StartsWith("DNS-мониторинг включён", StringComparison.Ordinal);
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null) { SetStatus("Ошибка получения DNS-события: " + args.EventException.Message); return; }
        using var record = args.EventRecord;
        if (record is null) return;
        try
        {
            var fields = ParseEventData(record.ToXml());
            var name = Limit(Get(fields, "QueryName"), 512);
            var type = Limit(Get(fields, "QueryType"), 64);
            var results = Limit(Get(fields, "QueryResults"), 4096);
            var status = Limit(Get(fields, "QueryStatus"), 128);
            var pidText = Get(fields, "ClientProcessId", "QueryProcessId", "ClientPID");
            int? pid = int.TryParse(pidText, out var parsedPid) && parsedPid >= 0 ? parsedPid : null;
            var processName = "(не определён)";
            string? imagePath = null;
            if (pid is int processId)
            {
                try { using var process = Process.GetProcessById(processId); processName = process.ProcessName; imagePath = process.MainModule?.FileName; }
                catch { processName = $"PID {processId}"; }
            }
            var query = NetworkMetadataAnalyzer.AnalyzeDns(record.TimeCreated ?? DateTime.Now, name, type, results, status, pid, processName, imagePath);
            QueryReceived?.Invoke(query);
        }
        catch (Exception ex) { SetStatus("DNS-событие получено, но разобрать его не удалось: " + ex.Message); }
    }

    private static Dictionary<string, string> ParseEventData(string xml)
    {
        var document = XDocument.Parse(xml);
        return document.Descendants().Where(element => element.Name.LocalName == "Data")
            .Where(element => element.Attribute("Name") is not null)
            .GroupBy(element => (string)element.Attribute("Name")!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Last().Value, StringComparer.OrdinalIgnoreCase);
    }

    private static string Get(IReadOnlyDictionary<string, string> fields, params string[] names) =>
        names.Select(name => fields.TryGetValue(name, out var value) ? value : null).FirstOrDefault(value => value is not null) ?? "";

    private static string Limit(string value, int maximum) => value.Length <= maximum ? value : value[..maximum] + "…";

    public void Dispose()
    {
        Stop();
        lock (sync) disposed = true;
    }
}

internal sealed record ManagedFirewallRule(
    string Name,
    string DisplayName,
    string Direction,
    string Action,
    bool Enabled,
    string Program,
    string RemoteAddress,
    string RemotePort,
    string LocalPort,
    string Protocol);

internal sealed record FirewallProfileStatus(
    string Name,
    bool Enabled,
    string DefaultInboundAction,
    string DefaultOutboundAction);

internal sealed record FirewallInventory(
    List<FirewallProfileStatus> Profiles,
    List<ManagedFirewallRule> Rules);

internal sealed record NetworkFirewallRequest(
    string Action,
    string? Name = null,
    string? DisplayName = null,
    string? Direction = null,
    string? ProgramPath = null,
    string? RemoteAddress = null,
    int LocalPort = 0,
    int RemotePort = 0);

internal sealed record NetworkOperationResult(bool Success, string Message);

internal static class NetworkTrafficAnalyzer
{
    private static readonly HashSet<int> UncommonSensitivePorts = [23, 1337, 4444, 5555, 6666, 6667, 31337];

    public static IReadOnlyList<TcpConnectionSnapshot> Analyze(IEnumerable<TcpConnectionRaw> source)
    {
        var rows = source.Where(row => row.ProcessId >= 0 && row.LocalPort is >= 0 and <= 65535 && row.RemotePort is >= 1 and <= 65535).ToList();
        var fanout = rows.GroupBy(row => row.ProcessId)
            .ToDictionary(group => group.Key, group => group.Select(row => NormalizeForComparison(row.RemoteAddress)).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        return rows.Select(row => AnalyzeOne(row, fanout.GetValueOrDefault(row.ProcessId, 0)))
            .OrderByDescending(row => row.RiskScore)
            .ThenBy(row => row.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.RemoteAddress, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static TcpConnectionSnapshot AnalyzeOne(TcpConnectionRaw row, int distinctRemoteCount)
    {
        var score = 0;
        var reasons = new List<string>();
        if (string.IsNullOrWhiteSpace(row.ImagePath))
        {
            score += 1;
            reasons.Add("Путь файла процесса недоступен для этой учётной записи.");
        }
        else if (IsUserWritablePath(row.ImagePath))
        {
            score += 2;
            reasons.Add("Образ запущен из пользовательской или временной папки.");
        }

        if (UncommonSensitivePorts.Contains(row.RemotePort))
        {
            score += 2;
            reasons.Add($"Удалённый TCP-порт {row.RemotePort} часто встречается в тестовых/административных инструментах; сам по себе не доказывает угрозу.");
        }

        if (IPAddress.TryParse(row.RemoteAddress, out var address) && IsPublicAddress(address))
        {
            score += 1;
            reasons.Add("Соединение направлено на внешний IP; репутация адреса локально не проверялась.");
        }

        if (distinctRemoteCount >= 40)
        {
            score += 2;
            reasons.Add($"У процесса {distinctRemoteCount} различных удалённых IP в текущем снимке; браузеры и синхронизация тоже могут создавать много соединений.");
        }

        var level = score switch
        {
            >= 4 => "Повышенный сигнал",
            >= 2 => "Требует внимания",
            1 => "Слабый сигнал",
            _ => "Явный сигнал не найден"
        };
        var explanation = reasons.Count == 0
            ? "Выраженных локальных сигналов нет; это не проверка содержимого трафика и не оценка репутации узла."
            : string.Join(" ", reasons);
        return new TcpConnectionSnapshot(row.ProcessId, row.ProcessName, row.ImagePath, row.LocalAddress, row.LocalPort,
            row.RemoteAddress, row.RemotePort, row.State, score, level, explanation);
    }

    internal static bool IsUserWritableImage(string path) => IsUserWritablePath(path);

    private static bool IsUserWritablePath(string path)
    {
        var normalized = path.Replace('/', '\\').ToLowerInvariant();
        return normalized.Contains("\\appdata\\local\\temp\\", StringComparison.Ordinal) ||
               normalized.Contains("\\appdata\\roaming\\", StringComparison.Ordinal) ||
               normalized.Contains("\\downloads\\", StringComparison.Ordinal) ||
               normalized.Contains("\\users\\public\\", StringComparison.Ordinal) ||
               normalized.Contains("\\programdata\\", StringComparison.Ordinal);
    }

    private static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal)
            return false;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var v6 = address.GetAddressBytes();
            return !(v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8);
        }
        if (address.AddressFamily != AddressFamily.InterNetwork) return true;
        var bytes = address.GetAddressBytes();
        return !(bytes[0] == 0 || bytes[0] == 10 || bytes[0] == 127 ||
                 (bytes[0] == 169 && bytes[1] == 254) ||
                 (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                 (bytes[0] == 192 && bytes[1] == 168) ||
                 (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) ||
                 (bytes[0] == 192 && bytes[1] == 0 && bytes[2] is 0 or 2) ||
                 (bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99) ||
                 (bytes[0] == 198 && bytes[1] is 18 or 19) ||
                 (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) ||
                 (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) ||
                 bytes[0] is >= 224 and <= 239 ||
                 bytes[0] >= 240);
    }

    private static string NormalizeForComparison(string value) =>
        IPAddress.TryParse(value, out var address) ? address.ToString() : value.Trim();
}

internal static class NetworkConnectionReader
{
    private const string SnapshotScript = @"
$ErrorActionPreference = 'Stop'
$processes = @{}
Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ExecutablePath -ErrorAction SilentlyContinue | ForEach-Object {
    $processes[[int]$_.ProcessId] = [pscustomobject]@{ Name = [string]$_.Name; Path = [string]$_.ExecutablePath }
}
$rows = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -notin @('Listen', 'Bound', 'Closed', 'TimeWait', 'DeleteTCB') } | ForEach-Object {
    $id = [int]$_.OwningProcess
    $name = ""PID $id""
    $path = $null
    if ($processes.ContainsKey($id)) {
        if (-not [string]::IsNullOrWhiteSpace($processes[$id].Name)) { $name = $processes[$id].Name }
        $path = $processes[$id].Path
    }
    [pscustomobject]@{
        ProcessId = $id; ProcessName = $name; ImagePath = $path
        LocalAddress = [string]$_.LocalAddress; LocalPort = [int]$_.LocalPort
        RemoteAddress = [string]$_.RemoteAddress; RemotePort = [int]$_.RemotePort
        State = [string]$_.State
    }
})
$json = ConvertTo-Json -InputObject $rows -Depth 4 -Compress
[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
";

    public static IReadOnlyList<TcpConnectionSnapshot> Read()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Снимок TCP-соединений доступен только в Windows.");
        var output = NetworkPowerShell.RunJson(SnapshotScript, TimeSpan.FromSeconds(45));
        var raw = JsonSerializer.Deserialize<List<TcpConnectionRaw>>(output, JsonOptions()) ?? [];
        return NetworkTrafficAnalyzer.Analyze(raw);
    }

    internal static JsonSerializerOptions JsonOptions() => new() { PropertyNameCaseInsensitive = true };
}

internal static class NetworkFirewallManager
{
    public const string ManagedGroup = "DefenderGuard.NetworkBlocks";
    private const string RulePrefix = "DefenderGuard.NetworkBlock.";
    private const string FirewallSnapshotScript = @"
$ErrorActionPreference = 'Stop'
$profiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ Name = [string]$_.Name; Enabled = [bool]$_.Enabled; DefaultInboundAction = [string]$_.DefaultInboundAction; DefaultOutboundAction = [string]$_.DefaultOutboundAction }
})
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group 'DefenderGuard.NetworkBlocks' -ErrorAction SilentlyContinue | ForEach-Object {
    $rule = $_
    $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Name = [string]$rule.Name; DisplayName = [string]$rule.DisplayName; Direction = [string]$rule.Direction
        Action = [string]$rule.Action; Enabled = [bool]$rule.Enabled; Program = [string]$app.Program
        RemoteAddress = (@($address.RemoteAddress) -join ','); RemotePort = (@($port.RemotePort) -join ',')
        LocalPort = (@($port.LocalPort) -join ','); Protocol = [string]$port.Protocol
    }
})
$json = ConvertTo-Json -InputObject ([pscustomobject]@{ Profiles = $profiles; Rules = $rules }) -Depth 6 -Compress
[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
";

    public static FirewallInventory ReadInventory()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Управление Windows Firewall доступно только в Windows.");
        var output = NetworkPowerShell.RunJson(FirewallSnapshotScript, TimeSpan.FromSeconds(45));
        return JsonSerializer.Deserialize<FirewallInventory>(output, NetworkConnectionReader.JsonOptions())
            ?? throw new InvalidOperationException("Не удалось разобрать состояние Windows Firewall.");
    }

    public static string CreateAddPayload(TcpConnectionSnapshot connection, string direction)
    {
        if (direction is not ("Inbound" or "Outbound")) throw new ArgumentException("Выберите входящее или исходящее направление.", nameof(direction));
        if (string.IsNullOrWhiteSpace(connection.ImagePath) || !Path.IsPathFullyQualified(connection.ImagePath) || !File.Exists(connection.ImagePath))
            throw new InvalidOperationException("Файл-образ этого процесса недоступен; правило для него не создаётся.");
        var remoteAddress = NormalizeRemoteAddress(connection.RemoteAddress);
        if (connection.RemotePort is < 1 or > 65535 || connection.LocalPort is < 1 or > 65535)
            throw new InvalidOperationException("У соединения недопустимый номер порта.");
        var path = Path.GetFullPath(connection.ImagePath);
        var matchPort = direction == "Outbound" ? connection.RemotePort : connection.LocalPort;
        var key = $"{direction}\n{path.ToUpperInvariant()}\n{remoteAddress}\n{matchPort}";
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..24];
        var displayDirection = direction == "Outbound" ? "Исходящий" : "Входящий";
        var endpoint = direction == "Outbound" ? $"{remoteAddress}:{connection.RemotePort}" : $"{remoteAddress} → локальный порт {connection.LocalPort}";
        var processName = Path.GetFileName(path);
        if (processName.Length > 36) processName = processName[..33] + "...";
        var request = new NetworkFirewallRequest("add", RulePrefix + digest,
            $"DefenderGuard: {displayDirection} {processName} {endpoint}", direction, path, remoteAddress,
            direction == "Inbound" ? connection.LocalPort : 0,
            direction == "Outbound" ? connection.RemotePort : 0);
        return Encode(request);
    }

    public static string CreateRemovePayload(ManagedFirewallRule rule)
    {
        ValidateManagedRuleName(rule.Name);
        return Encode(new NetworkFirewallRequest("remove", Name: rule.Name));
    }

    public static string GetRuleName(TcpConnectionSnapshot connection, string direction)
    {
        if (string.IsNullOrWhiteSpace(connection.ImagePath) || !Path.IsPathFullyQualified(connection.ImagePath)) return string.Empty;
        if (direction is not ("Inbound" or "Outbound") || !IPAddress.TryParse(connection.RemoteAddress, out var ip)) return string.Empty;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var port = direction == "Outbound" ? connection.RemotePort : connection.LocalPort;
        var key = $"{direction}\n{Path.GetFullPath(connection.ImagePath).ToUpperInvariant()}\n{ip}\n{port}";
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..24];
        return RulePrefix + digest;
    }

    public static NetworkOperationResult ExecuteElevated(string encodedPayload)
    {
        if (!OperatingSystem.IsWindows()) return new(false, "Правила Windows Firewall доступны только в Windows.");
        if (!IsAdministrator()) return new(false, "Для создания или удаления правила требуются права администратора; подтвердите UAC.");
        if (encodedPayload.Length > 8192) return new(false, "Запрос Firewall слишком длинный.");
        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(encodedPayload));
            var request = JsonSerializer.Deserialize<NetworkFirewallRequest>(json, NetworkConnectionReader.JsonOptions())
                ?? throw new InvalidOperationException("Пустой запрос.");
            var script = BuildActionScript(request);
            var result = NetworkPowerShell.Run(script, TimeSpan.FromSeconds(60));
            return result.ExitCode == 0
                ? new(true, result.Output.Contains("RULE_REMOVED", StringComparison.Ordinal)
                    ? "Созданное DefenderGuard правило Windows Firewall удалено."
                    : "Создано адресное правило блокировки Windows Firewall.")
                : new(false, "Windows Firewall не применил изменение: " + Short(string.IsNullOrWhiteSpace(result.Error) ? result.Output : result.Error));
        }
        catch (Exception ex) { return new(false, "Не удалось применить изменение Firewall: " + ex.Message); }
    }

    private static string BuildActionScript(NetworkFirewallRequest request)
    {
        if (request.Action == "add")
        {
            if (request.Direction is not ("Inbound" or "Outbound")) throw new InvalidOperationException("Недопустимое направление правила.");
            if (string.IsNullOrWhiteSpace(request.ProgramPath) || !Path.IsPathFullyQualified(request.ProgramPath) || !File.Exists(request.ProgramPath))
                throw new InvalidOperationException("Путь исполняемого файла отсутствует или не является абсолютным.");
            var address = NormalizeRemoteAddress(request.RemoteAddress ?? "");
            var expectedPort = request.Direction == "Outbound" ? request.RemotePort : request.LocalPort;
            if (expectedPort is < 1 or > 65535) throw new InvalidOperationException("Недопустимый порт правила.");
            ValidateManagedRuleName(request.Name ?? "");
            if (string.IsNullOrWhiteSpace(request.DisplayName) || request.DisplayName.Length > 180)
                throw new InvalidOperationException("Недопустимое отображаемое имя правила.");
            var verifiedRequest = request with { ProgramPath = Path.GetFullPath(request.ProgramPath), RemoteAddress = address };
            var expectedName = ComputeRuleName(verifiedRequest, expectedPort);
            if (!string.Equals(request.Name, expectedName, StringComparison.Ordinal))
                throw new InvalidOperationException("Имя правила не соответствует его параметрам.");
        }
        else if (request.Action == "remove")
        {
            ValidateManagedRuleName(request.Name ?? "");
        }
        else throw new InvalidOperationException("Неизвестная операция Firewall.");

        var requestJson = JsonSerializer.Serialize(request);
        var data = Convert.ToBase64String(Encoding.UTF8.GetBytes(requestJson));
        var action = request.Action == "add" ? @"
$d = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + data + @"')) | ConvertFrom-Json
$existing = Get-NetFirewallRule -PolicyStore PersistentStore -Name $d.Name -ErrorAction SilentlyContinue
if ($null -ne $existing) { throw 'A rule with this managed name already exists. Remove it in DefenderGuard first.' }
$p = @{
  Name = [string]$d.Name; DisplayName = [string]$d.DisplayName; Group = 'DefenderGuard.NetworkBlocks'
  Description = 'Created explicitly by DefenderGuard for one TCP endpoint. Remove from DefenderGuard or Windows Firewall.'
  Direction = [string]$d.Direction; Action = 'Block'; Program = [string]$d.ProgramPath
  RemoteAddress = [string]$d.RemoteAddress; Protocol = 'TCP'; Profile = 'Any'; Enabled = 'True'; PolicyStore = 'PersistentStore'
}
if ($d.Direction -eq 'Outbound') { $p.RemotePort = [string]$d.RemotePort } else { $p.LocalPort = [string]$d.LocalPort }
New-NetFirewallRule @p -ErrorAction Stop | Out-Null
[Console]::Out.Write('RULE_ADDED')
" : @"
$d = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + data + @"')) | ConvertFrom-Json
$r = Get-NetFirewallRule -PolicyStore PersistentStore -Name $d.Name -ErrorAction Stop
if ($r.Group -ne 'DefenderGuard.NetworkBlocks' -or $r.Action -ne 'Block' -or $r.DisplayName -notlike 'DefenderGuard:*') { throw 'The selected rule is not a DefenderGuard-managed block rule.' }
Remove-NetFirewallRule -InputObject $r -ErrorAction Stop -Confirm:$false
[Console]::Out.Write('RULE_REMOVED')
";
        return "$ErrorActionPreference = 'Stop'\ntry {\nImport-Module NetSecurity -ErrorAction Stop\n" + action + "\n} catch { [Console]::Error.Write($_.Exception.Message); exit 1 }";
    }

    private static string ComputeRuleName(NetworkFirewallRequest request, int port)
    {
        var path = Path.GetFullPath(request.ProgramPath!);
        var direction = request.Direction!;
        var key = $"{direction}\n{path.ToUpperInvariant()}\n{request.RemoteAddress}\n{port}";
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..24];
        return RulePrefix + digest;
    }

    private static string Encode(NetworkFirewallRequest request) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(request));

    private static void ValidateManagedRuleName(string name)
    {
        if (!Regex.IsMatch(name, @"^DefenderGuard\.NetworkBlock\.[A-F0-9]{24}$", RegexOptions.CultureInvariant))
            throw new InvalidOperationException("Правило не принадлежит пространству имён DefenderGuard.");
    }

    private static string NormalizeRemoteAddress(string input)
    {
        if (!IPAddress.TryParse(input, out var address)) throw new InvalidOperationException("Удалённый адрес не является корректным IP.");
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(address) ||
            address.IsIPv6Multicast || address.IsIPv6LinkLocal || address.AddressFamily == AddressFamily.InterNetwork && IsIpv4MulticastOrBroadcast(address))
            throw new InvalidOperationException("Нельзя создать точечное правило для unspecified, loopback, multicast или link-local адреса.");
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            throw new InvalidOperationException("IPv6-адрес со scope ID не поддерживается этим правилом.");
        return address.ToString();
    }

    private static bool IsIpv4MulticastOrBroadcast(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return b[0] is >= 224 and <= 239 || (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255);
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static string Short(string value)
    {
        var text = string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return text.Length <= 600 ? text : text[..600] + "…";
    }
}

internal static class NetworkPowerShell
{
    private static string Short(string value)
    {
        var text = string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return text.Length <= 600 ? text : text[..600] + "…";
    }

    public static string RunJson(string script, TimeSpan timeout)
    {
        var output = Run(script, timeout);
        if (output.ExitCode != 0)
            throw new InvalidOperationException("PowerShell NetworkSecurity/TCP-команда завершилась с ошибкой: " + Short(output.Error));
        var payload = output.Output.Trim();
        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(payload));
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("PowerShell вернул некорректный JSON-контейнер. " + Short(output.Error), ex);
        }
    }

    public static (int ExitCode, string Output, string Error) Run(string script, TimeSpan timeout)
    {
        if (!OperatingSystem.IsWindows()) return (-1, "", "PowerShell Windows доступен только в Windows.");
        try
        {
            var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(powershell)) return (-1, "", "Windows PowerShell 5.1 не найден.");
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var start = new ProcessStartInfo
            {
                FileName = powershell,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            start.ArgumentList.Add("-NoLogo");
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-EncodedCommand");
            start.ArgumentList.Add(encoded);
            using var process = Process.Start(start);
            if (process is null) return (-1, "", "Не удалось запустить Windows PowerShell.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit((int)timeout.TotalMilliseconds))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return (-1, "", "Истекло время ожидания команды Windows PowerShell.");
            }
            Task.WaitAll(stdout, stderr);
            return (process.ExitCode, stdout.Result.Trim(), stderr.Result.Trim());
        }
        catch (Exception ex) { return (-1, "", ex.Message); }
    }
}