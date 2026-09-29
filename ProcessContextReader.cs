using System.Management;

namespace DemoGuard;

internal sealed record ProcessContextSnapshot(
    int ProcessId,
    int ParentProcessId,
    string ProcessName,
    string? ParentProcessName,
    string? ImagePath,
    string? CommandLine,
    string ParentChain,
    int TcpConnections,
    int HighTcpSignals,
    int MediumTcpSignals,
    string NetworkSummary);

internal static class ProcessContextReader
{
    public static IReadOnlyList<ProcessContextSnapshot> Read(
        IReadOnlyList<TcpConnectionSnapshot>? connections = null)
    {
        if (!OperatingSystem.IsWindows())
            return Array.Empty<ProcessContextSnapshot>();

        var tcpByPid = (connections ?? Array.Empty<TcpConnectionSnapshot>())
            .GroupBy(item => item.ProcessId)
            .ToDictionary(
                group => group.Key,
                group => group.ToArray());

        var raw = new Dictionary<int, RawProcess>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process");
        using var results = searcher.Get();

        foreach (ManagementObject item in results)
        {
            try
            {
                var pid = Convert.ToInt32(item["ProcessId"], System.Globalization.CultureInfo.InvariantCulture);
                if (pid <= 0) continue;
                var parentPid = item["ParentProcessId"] is null
                    ? 0
                    : Convert.ToInt32(item["ParentProcessId"], System.Globalization.CultureInfo.InvariantCulture);
                raw[pid] = new RawProcess(
                    pid,
                    parentPid,
                    item["Name"]?.ToString() ?? "(неизвестно)",
                    item["ExecutablePath"]?.ToString(),
                    item["CommandLine"]?.ToString());
            }
            catch { }
        }

        var snapshots = new List<ProcessContextSnapshot>();
        foreach (var process in raw.Values
                     .Where(item => !IsIgnored(item.Name))
                     .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(item => item.ProcessId)
                     .Take(750))
        {
            var chain = BuildParentChain(process, raw);
            var tcp = tcpByPid.TryGetValue(process.ProcessId, out var rows)
                ? rows
                : Array.Empty<TcpConnectionSnapshot>();
            var high = tcp.Count(item => item.RiskScore >= 4);
            var medium = tcp.Count(item => item.RiskScore is >= 2 and < 4);
            var networkSummary = tcp.Length == 0
                ? "TCP-соединений в сохранённом снимке нет."
                : $"TCP: {tcp.Length}; повышенных: {high}; требующих внимания: {medium}.";

            var parentName = raw.TryGetValue(process.ParentProcessId, out var parent)
                ? $"{parent.Name} (PID {parent.ProcessId})"
                : process.ParentProcessId > 0 ? $"PID {process.ParentProcessId}" : "(нет)";

            snapshots.Add(new ProcessContextSnapshot(
                process.ProcessId,
                process.ParentProcessId,
                process.Name,
                parentName,
                process.ImagePath,
                Truncate(process.CommandLine, 2000),
                chain,
                tcp.Length,
                high,
                medium,
                networkSummary));
        }

        return snapshots;
    }

    private static string BuildParentChain(RawProcess process, IReadOnlyDictionary<int, RawProcess> all)
    {
        var chain = new List<string> { FormatProcess(process) };
        var visited = new HashSet<int> { process.ProcessId };
        var current = process;

        for (var depth = 0; depth < 5 && current.ParentProcessId > 0; depth++)
        {
            if (!visited.Add(current.ParentProcessId)) break;
            if (!all.TryGetValue(current.ParentProcessId, out var parent)) break;
            chain.Insert(0, FormatProcess(parent));
            current = parent;
        }

        return string.Join(" → ", chain);
    }

    private static string FormatProcess(RawProcess process) =>
        $"{process.Name} (PID {process.ProcessId})";

    private static bool IsIgnored(string name) =>
        name.Equals("DefenderGuard.exe", StringComparison.OrdinalIgnoreCase)
        || name.Equals("MpCmdRun.exe", StringComparison.OrdinalIgnoreCase);

    private static string? Truncate(string? value, int maximum) =>
        string.IsNullOrWhiteSpace(value) || value.Length <= maximum ? value : value[..maximum] + "…";

    private sealed record RawProcess(
        int ProcessId,
        int ParentProcessId,
        string Name,
        string? ImagePath,
        string? CommandLine);
}