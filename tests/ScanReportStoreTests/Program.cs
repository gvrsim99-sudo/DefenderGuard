using System.Text;
namespace DemoGuard;

internal sealed record SystemScanReport(
    DateTime StartedAt,
    DateTime FinishedAt,
    int DefenderExitCode,
    int StartupExamined,
    int StartupUnreadable,
    int StartupFindings,
    int ProcessExamined,
    int ProcessUnreadable,
    int ProcessFindings,
    int HighSignals,
    int MediumSignals);

internal sealed record DefenderCommandResult(int ExitCode, string Output);

internal static class Program
{
    private static readonly string StorePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DemoGuard", "scan-history.json");

    public static int Main()
    {
        var directory = Path.GetDirectoryName(StorePath)!;
        Directory.CreateDirectory(directory);
        var backup = StorePath + ".stage1-backup";
        var hadOriginal = File.Exists(StorePath);
        if (hadOriginal) File.Copy(StorePath, backup, overwrite: true);

        try
        {
            if (File.Exists(StorePath)) File.Delete(StorePath);
            var firstId = Guid.NewGuid();
            var secondId = Guid.NewGuid();
            var finding = new ScanReportFindingSnapshot(
                DateTime.Now.AddMinutes(-1),
                "Тест",
                @"C:\Temp\sample.ps1",
                @"C:\Temp\sample.ps1",
                5,
                "Medium",
                ["Причина A", "Причина B"]);
            var tcp = new TcpConnectionSnapshot(1234, "sample.exe", @"C:\\Apps\\sample.exe", "127.0.0.1", 50123, "203.0.113.10", 443, "Established", 2, "Требует внимания", "test signal");
            var firewall = new ManagedFirewallRule("DG_TEST", "DG test block", "Outbound", "Block", true, @"C:\\Apps\\sample.exe", "203.0.113.10", "443", "Any", "TCP");
            var network = new SystemScanNetworkSnapshot(DateTime.Now, [tcp], [], [new FirewallProfileStatus("Domain", true, "Block", "Allow")], [firewall], null, null);
            var processContext = new ProcessContextSnapshot(1234, 777, "sample.exe", "explorer.exe (PID 777)", @"C:\\Apps\\sample.exe", "sample.exe --test", "explorer.exe (PID 777) → sample.exe (PID 1234)", 1, 0, 1, "TCP: 1; повышенных: 0; требующих внимания: 1.");
            var first = NewSnapshot(firstId, DateTime.Now.AddMinutes(-2), [finding], network, [processContext]);
            var second = NewSnapshot(secondId, DateTime.Now, [finding], network, [processContext]);

            ScanReportStore.Save(first);
            ScanReportStore.Save(second);
            var loaded = ScanReportStore.Load();

            Assert(loaded.Count == 2, "ожидались две записи");
            Assert(loaded[0].Id == secondId, "последняя проверка должна быть первой");
            Assert(loaded[0].Findings.Count == 1, "детальный сигнал не сохранился");
            Assert(loaded[0].Findings[0].Reasons.Count == 2, "причины сигнала потерялись");
            var savedNetwork = loaded[0].Network ?? throw new InvalidOperationException("FAIL: сетевой контекст не сохранился");
            Assert(savedNetwork.TcpConnections.Count == 1, "TCP-контекст не сохранился");
            Assert(savedNetwork.FirewallRules.Count == 1, "Firewall-контекст не сохранился");
            Assert(savedNetwork.TcpConnections[0].ProcessId == 1234, "PID процесса не сохранился");
            var savedProcess = loaded[0].ProcessContexts?.SingleOrDefault() ?? throw new InvalidOperationException("FAIL: контекст процесса не сохранился");
            Assert(savedProcess.ParentProcessId == 777, "Parent PID не сохранился");
            Assert(savedProcess.CommandLine == "sample.exe --test", "командная строка не сохранилась");
            Assert(savedProcess.ParentChain.Contains("explorer.exe (PID 777)", StringComparison.Ordinal), "цепочка родителей не сохранилась");

            var action = new ScanReportActionSnapshot(
                DateTime.Now,
                secondId,
                finding.Source,
                finding.Subject,
                finding.FilePath,
                "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
                "defender-rescan",
                "Defender завершил точечную проверку; код 0.",
                0);
            Assert(ScanReportStore.AppendAction(action), "действие не добавилось в scan-history.json");
            var afterAction = ScanReportStore.Load();
            var savedAction = afterAction[0].Actions?.SingleOrDefault() ?? throw new InvalidOperationException("FAIL: структурированное действие не сохранилось");
            Assert(savedAction.ReportId == secondId, "ReportId действия не сохранился");
            Assert(savedAction.Sha256 == action.Sha256, "SHA-256 действия не сохранился");
            Assert(savedAction.Action == "defender-rescan", "тип действия не сохранился");
            Assert(savedAction.Result.Contains("код 0", StringComparison.Ordinal), "результат действия не сохранился");
            Assert(savedAction.DefenderExitCode == 0, "код Defender в истории не сохранился");
            Console.WriteLine("PASS: scan report save/load, finding details, TCP PID/EXE, Firewall/process context and structured actions.");
            return 0;
        }
        finally
        {
            if (File.Exists(StorePath)) File.Delete(StorePath);
            if (hadOriginal) File.Move(backup, StorePath, overwrite: true);
            else if (File.Exists(backup)) File.Delete(backup);
        }
    }

    private static SystemScanReportSnapshot NewSnapshot(Guid id, DateTime finishedAt, IReadOnlyList<ScanReportFindingSnapshot> findings, SystemScanNetworkSnapshot network, IReadOnlyList<ProcessContextSnapshot> processContexts) =>
        new(id, finishedAt.AddMinutes(-1), finishedAt, 0, "defender output", 10, 0, 1, 20, 2, 1, 0, 1, findings, network, processContexts);

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("FAIL: " + message);
    }
}