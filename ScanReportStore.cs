using System.Text.Json;
using System.Text.Json.Serialization;

namespace DemoGuard;

internal sealed record ScanReportFindingSnapshot(
    DateTime ObservedAt,
    string Source,
    string Subject,
    string? FilePath,
    int Score,
    string Risk,
    IReadOnlyList<string> Reasons);

internal sealed record ScanReportActionSnapshot(
    DateTime OccurredAt,
    Guid ReportId,
    string Source,
    string Subject,
    string? FilePath,
    string? Sha256,
    string Action,
    string Result,
    int? DefenderExitCode);

internal sealed record SystemScanReportSnapshot(
    Guid Id,
    DateTime StartedAt,
    DateTime FinishedAt,
    int DefenderExitCode,
    string DefenderOutput,
    int StartupExamined,
    int StartupUnreadable,
    int StartupFindings,
    int ProcessExamined,
    int ProcessUnreadable,
    int ProcessFindings,
    int HighSignals,
    int MediumSignals,
    IReadOnlyList<ScanReportFindingSnapshot> Findings,
    SystemScanNetworkSnapshot? Network = null,
    IReadOnlyList<ProcessContextSnapshot>? ProcessContexts = null,
    IReadOnlyList<ScanReportActionSnapshot>? Actions = null);

internal sealed record SystemScanNetworkSnapshot(
    DateTime CapturedAt,
    IReadOnlyList<TcpConnectionSnapshot> TcpConnections,
    IReadOnlyList<DnsQuerySnapshot> DnsEvents,
    IReadOnlyList<FirewallProfileStatus> FirewallProfiles,
    IReadOnlyList<ManagedFirewallRule> FirewallRules,
    string? TcpError,
    string? FirewallError);

internal static class ScanReportStore
{
    private const int MaxReports = 30;
    private static readonly object Sync = new();
    private const int MaxFindingsPerReport = 500;
    private static readonly string AppData =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DemoGuard");
    private static readonly string FilePath = Path.Combine(AppData, "scan-history.json");
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static IReadOnlyList<SystemScanReportSnapshot> Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return Array.Empty<SystemScanReportSnapshot>();
            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<List<SystemScanReportSnapshot>>(json, JsonOptions)
                ?.Where(report => report.StartedAt <= report.FinishedAt)
                .OrderByDescending(report => report.FinishedAt)
                .Take(MaxReports)
                .ToArray()
                ?? Array.Empty<SystemScanReportSnapshot>();
        }
        catch
        {
            return Array.Empty<SystemScanReportSnapshot>();
        }
    }

    public static void Save(SystemScanReportSnapshot report)
    {
        lock (Sync)
        {
            Directory.CreateDirectory(AppData);
            var reports = Load().Where(item => item.Id != report.Id)
                .Prepend(report)
                .OrderByDescending(item => item.FinishedAt)
                .Take(MaxReports)
                .ToArray();

            var tempPath = FilePath + ".tmp";
            var json = JsonSerializer.Serialize(reports, JsonOptions);
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, FilePath, overwrite: true);
        }
    }

    public static SystemScanReportSnapshot Create(
        SystemScanReport report,
        DefenderCommandResult defenderResult,
        IEnumerable<HeuristicFinding> findings,
        SystemScanNetworkSnapshot? network = null,
        IReadOnlyList<ProcessContextSnapshot>? processContexts = null)
    {
        var snapshots = findings
            .OrderByDescending(item => item.Score)
            .ThenByDescending(item => item.ObservedAt)
            .Take(MaxFindingsPerReport)
            .Select(item => new ScanReportFindingSnapshot(
                item.ObservedAt,
                item.Source,
                item.Subject,
                item.FilePath,
                item.Score,
                item.Risk.ToString(),
                item.Reasons.ToArray()))
            .ToArray();

        var output = defenderResult.Output ?? string.Empty;
        if (output.Length > 12_000) output = output[..12_000] + "…";

        return new SystemScanReportSnapshot(
            Guid.NewGuid(),
            report.StartedAt,
            report.FinishedAt,
            report.DefenderExitCode,
            output,
            report.StartupExamined,
            report.StartupUnreadable,
            report.StartupFindings,
            report.ProcessExamined,
            report.ProcessUnreadable,
            report.ProcessFindings,
            report.HighSignals,
            report.MediumSignals,
            snapshots,
            network,
            processContexts,
            Array.Empty<ScanReportActionSnapshot>());
    }

    public static bool AppendAction(ScanReportActionSnapshot action)
    {
        if (action.ReportId == Guid.Empty) return false;
        lock (Sync)
        {
            try
            {
                Directory.CreateDirectory(AppData);
                var reports = Load().ToList();
                var index = reports.FindIndex(report => report.Id == action.ReportId);
                if (index < 0) return false;

                var current = reports[index];
                var actions = (current.Actions ?? Array.Empty<ScanReportActionSnapshot>())
                    .Prepend(action)
                    .Take(200)
                    .ToArray();
                reports[index] = current with { Actions = actions };

                var tempPath = FilePath + ".tmp";
                var json = JsonSerializer.Serialize(
                    reports.OrderByDescending(item => item.FinishedAt).Take(MaxReports),
                    JsonOptions);
                File.WriteAllText(tempPath, json);
                File.Move(tempPath, FilePath, overwrite: true);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
internal static class ScanReportSnapshotMapper
{
    public static SystemScanReport ToReport(SystemScanReportSnapshot snapshot) =>
        new(
            snapshot.StartedAt,
            snapshot.FinishedAt,
            snapshot.DefenderExitCode,
            snapshot.StartupExamined,
            snapshot.StartupUnreadable,
            snapshot.StartupFindings,
            snapshot.ProcessExamined,
            snapshot.ProcessUnreadable,
            snapshot.ProcessFindings,
            snapshot.HighSignals,
            snapshot.MediumSignals);

    public static HeuristicFinding ToFinding(ScanReportFindingSnapshot snapshot) =>
        new(
            snapshot.ObservedAt,
            snapshot.Source,
            snapshot.Subject,
            snapshot.FilePath,
            snapshot.Score,
            Enum.TryParse<HeuristicRisk>(snapshot.Risk, ignoreCase: true, out var risk) ? risk : HeuristicRisk.Low,
            snapshot.Reasons);
}