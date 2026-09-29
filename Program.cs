using System.Diagnostics;
using System.Drawing;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace DemoGuard;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Any(arg => arg.Equals("--scheduled-scan", StringComparison.OrdinalIgnoreCase)))
            return ScheduledScanRunner.Run();
        if (args.Any(arg => arg.Equals("--self-protection-service", StringComparison.OrdinalIgnoreCase)))
        {
            if (Environment.UserInteractive)
            {
                ApplicationConfiguration.Initialize();
                MessageBox.Show("Фоновый режим запускается только зарегистрированной службой Windows. Для управления используйте раздел «Параметры».", "DefenderGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return 2;
            }
            SelfProtectionServiceHost.Run();
            return 0;
        }

        ApplicationConfiguration.Initialize();
        var networkActionIndex = Array.FindIndex(args, arg => arg.Equals("--network-firewall-action", StringComparison.OrdinalIgnoreCase));
        if (networkActionIndex >= 0)
        {
            var result = networkActionIndex + 1 < args.Length
                ? NetworkFirewallManager.ExecuteElevated(args[networkActionIndex + 1])
                : new NetworkOperationResult(false, "Не переданы параметры сетевого правила.");
            MessageBox.Show(result.Message, result.Success ? "Windows Firewall — DefenderGuard" : "Windows Firewall — ошибка",
                MessageBoxButtons.OK, result.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            return result.Success ? 0 : 1;
        }

        var diagnosticCommand = Array.FindIndex(args, arg => arg.Equals("--self-protection-diagnostic", StringComparison.OrdinalIgnoreCase));
        if (diagnosticCommand >= 0)
        {
            var operation = diagnosticCommand + 1 < args.Length ? args[diagnosticCommand + 1] : "status";
            var result = operation.Equals("install", StringComparison.OrdinalIgnoreCase)
                ? SelfProtectionManager.Install()
                : operation.Equals("disable", StringComparison.OrdinalIgnoreCase)
                    ? SelfProtectionManager.Disable()
                    : null;
            if (result is not null)
            {
                Console.WriteLine($"success={result.Success}");
                Console.WriteLine(result.Message);
                return result.Success ? 0 : 1;
            }

            var status = SelfProtectionManager.GetStatus();
            Console.WriteLine($"installed={status.Installed}");
            Console.WriteLine($"running={status.Running}");
            Console.WriteLine(status.Message);
            return status.Installed && status.Running ? 0 : 2;
        }

        if (args.Any(arg => arg.Equals("--update-check", StringComparison.OrdinalIgnoreCase)))
        {
            var result = AppUpdater.CheckAsync().GetAwaiter().GetResult();
            Console.WriteLine($"success={result.Success}");
            Console.WriteLine($"available={result.UpdateAvailable}");
            if (result.Version is not null) Console.WriteLine($"version={result.Version}");
            Console.WriteLine(result.Message);
            return result.Success ? 0 : 1;
        }

        var updateInstallIndex = Array.FindIndex(args, arg => arg.Equals("--update-install", StringComparison.OrdinalIgnoreCase));
        if (updateInstallIndex >= 0)
        {
            var packageIndex = updateInstallIndex + 1;
            var hashIndex = updateInstallIndex + 2;
            return packageIndex < args.Length && hashIndex < args.Length
                ? UpdateInstallerRunner.Run(args[packageIndex], args[hashIndex])
                : 1;
        }

        var managementCommand = args.FirstOrDefault(arg =>
            arg.Equals("--install-self-protection", StringComparison.OrdinalIgnoreCase) ||
            arg.Equals("--disable-self-protection", StringComparison.OrdinalIgnoreCase));
        if (managementCommand is not null)
        {
            var result = managementCommand.Equals("--install-self-protection", StringComparison.OrdinalIgnoreCase)
                ? SelfProtectionManager.Install()
                : SelfProtectionManager.Disable();
            MessageBox.Show(result.Message, result.Success ? "Самозащита DefenderGuard" : "Самозащита — ошибка",
                MessageBoxButtons.OK, result.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            return result.Success ? 0 : 1;
        }

        var mutexName = SelfProtectionPaths.SingleInstanceMutexName;
        using var singleInstance = new Mutex(initiallyOwned: true, mutexName, out var createdNew);
        if (!createdNew) return 0;
        Application.Run(new MainForm());
        return 0;
    }
}

internal sealed record DuplicateSelectionItem(DuplicateGroup Group, DuplicateFile File);

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

internal sealed class MainForm : Form
{
    private static readonly Color Background = Color.FromArgb(14, 23, 34);
    private static readonly Color Surface = Color.FromArgb(22, 34, 48);
    private static readonly Color SurfaceAlt = Color.FromArgb(28, 43, 59);
    private static readonly Color TextMain = Color.FromArgb(237, 243, 248);
    private static readonly Color TextMuted = Color.FromArgb(151, 169, 185);
    private static readonly Color Green = Color.FromArgb(40, 201, 135);
    private static readonly Color Amber = Color.FromArgb(245, 183, 76);
    private static readonly string Eicar = EicarScanner.TestText;
    private static readonly string AppData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DemoGuard");
    private static readonly string QuarantineDirectory = Path.Combine(AppData, "Quarantine");
    private static readonly string HistoryFile = Path.Combine(AppData, "history.log");
    private static readonly string ScheduleFile = Path.Combine(AppData, "schedule.json");

    private readonly Panel content = new() { Dock = DockStyle.Fill, Padding = new Padding(26, 20, 26, 20), BackColor = Background, AutoScroll = true };
    private readonly Panel sidebar = new() { Dock = DockStyle.Left, Width = 228, Padding = new Padding(18, 20, 14, 16), BackColor = Color.FromArgb(18, 29, 42) };
    private readonly Label statusLine = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly CheckBox processMonitorToggle = new() { Text = "Мониторить запуски новых процессов (только пока приложение открыто)", AutoSize = true, ForeColor = TextMain, BackColor = Background };
    private readonly CheckBox restorePointToggle = new() { Text = "Создавать/проверять точку восстановления перед сканированиями", AutoSize = true, ForeColor = TextMain, BackColor = Surface };
    private readonly Label restorePointPolicyStatus = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F) };
    private readonly Label processMonitorStatus = new() { AutoSize = false, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), AutoEllipsis = true };
    private readonly ProgressBar progress = new() { Height = 8, Dock = DockStyle.Top, Visible = false, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 24 };
    private readonly FlowLayoutPanel detections = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Surface };
    private readonly FlowLayoutPanel heuristicRows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Background };
    private readonly Label heuristicSummary = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly List<HeuristicFinding> heuristicFindings = [];
    private readonly Panel heuristicPage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false };
    private readonly Panel fileAnalysisPage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false };
    private readonly ListView localAnalysisRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly ListView fileRulesRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly Label localAnalysisSummary = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Label fileRuleStatus = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F) };
    private readonly TextBox manualRuleHash = new() { Width = 420, PlaceholderText = "SHA-256: 64 шестнадцатеричных символа" };
    private readonly TextBox manualRuleNote = new() { Width = 220, PlaceholderText = "Причина / заметка" };
    private readonly ComboBox manualRuleKind = new() { Width = 155, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly List<LocalFileAnalysisResult> localAnalysisResults = [];
    private LocalFileLists currentFileLists = new([], []);
    private readonly Panel networkPage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false };
    private readonly ListView networkConnectionsRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly ListView udpEndpointRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly ListView dnsQueryRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly ListView networkFirewallRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly Label networkSummary = new() { AutoSize = false, Width = 940, Height = 18, AutoEllipsis = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Label udpSummary = new() { Dock = DockStyle.Top, Height = 24, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F), AutoEllipsis = true };
    private readonly Label dnsSummary = new() { Dock = DockStyle.Top, Height = 24, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F), AutoEllipsis = true };
    private readonly Label networkFirewallStatus = new() { AutoSize = false, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), AutoEllipsis = true };
    private readonly CheckBox networkAutoRefresh = new() { Text = "Автообновление каждые 10 секунд, пока открыта эта вкладка", AutoSize = true, ForeColor = TextMain, BackColor = Surface };
    private readonly CheckBox dnsMonitorToggle = new() { Text = "Мониторить новые DNS-события, пока открыта вкладка «Сеть»", AutoSize = true, ForeColor = TextMain, BackColor = Surface };
    private readonly ComboBox networkBlockDirection = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 300 };
    private readonly Button networkRefreshButton = new();
    private readonly Button networkBlockButton = new();
    private readonly Button networkRemoveButton = new();
    private readonly System.Windows.Forms.Timer networkTimer = new() { Interval = 10_000 };
    private readonly DnsMonitorService dnsMonitor = new();
    private IReadOnlyList<TcpConnectionSnapshot> networkConnections = Array.Empty<TcpConnectionSnapshot>();
    private IReadOnlyList<UdpEndpointSnapshot> udpEndpoints = Array.Empty<UdpEndpointSnapshot>();
    private readonly List<DnsQuerySnapshot> dnsQueries = [];
    private IReadOnlyList<ManagedFirewallRule> managedNetworkRules = Array.Empty<ManagedFirewallRule>();
    private IReadOnlyList<FirewallProfileStatus> firewallProfiles = Array.Empty<FirewallProfileStatus>();
    private bool networkBusy;
    private bool networkFirewallBusy;
    private readonly FlowLayoutPanel quarantineRows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Background };
    private readonly FlowLayoutPanel historyRows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Background };
    private readonly Label quarantineStatus = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F) };
    private readonly Panel pages = new() { Dock = DockStyle.Fill, BackColor = Background };
    private readonly Panel homePage = new() { Dock = DockStyle.Fill, BackColor = Background, AutoScroll = true };
    private readonly Panel reportPage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false, AutoScroll = true };
    private readonly FlowLayoutPanel reportRows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Background, Padding = new Padding(4) };
    private readonly Label reportStatus = new() { AutoSize = false, Height = 24, Width = 940, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F), AutoEllipsis = true };
    private DateTime? reportRefreshedAt;
    private readonly Panel quarantinePage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false };
    private readonly Panel historyPage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false };
    private readonly Panel cleanupPage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false, AutoScroll = true };
    private readonly FlowLayoutPanel cleanupRows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Surface, Padding = new Padding(4) };
    private readonly Label cleanupSummary = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Label cleanupStatus = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F) };
    private readonly Button cleanupScanButton = new();
    private readonly Button cleanupSelectAllButton = new();
    private readonly Button cleanupClearButton = new();
    private readonly Button cleanupRunButton = new();
    private readonly Button safeOptimizationButton = new();
    private readonly Button fullSystemScanButton = new();
    private readonly Button duplicateScanButton = new();
    private readonly Button duplicateSelectAllButton = new();
    private readonly Button duplicateClearButton = new();
    private readonly Button duplicateDeleteButton = new();
    private readonly Label duplicateSummary = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Label duplicateSelectionSummary = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F) };
    private readonly Label duplicateStatus = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F) };
    private readonly FlowLayoutPanel duplicateRows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Surface, Padding = new Padding(4), Visible = false };
    private bool duplicateRowsUpdating;
    private IReadOnlyList<CleanupTarget> cleanupTargets = Array.Empty<CleanupTarget>();
    private DuplicateScanResult? duplicateScanResult;
    private readonly Panel settingsPage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false, AutoScroll = true };
    private readonly Label selfProtectionStatusLabel = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Panel schedulePage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false };
    private readonly Panel storagePage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false, AutoScroll = true };
    private readonly Panel computerInfoPage = new() { Dock = DockStyle.Fill, BackColor = Background, Visible = false, AutoScroll = true };
    private readonly ListView storageVolumeRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly ListView physicalDiskRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly FlowLayoutPanel liveMetricCards = new() { Dock = DockStyle.Fill, WrapContents = false, BackColor = Background, Padding = new Padding(4) };
    private readonly ListView gpuLiveRows = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false, BackColor = Surface, ForeColor = TextMain, BorderStyle = BorderStyle.None };
    private readonly FlowLayoutPanel computerInfoRows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, BackColor = Background, Padding = new Padding(4) };
    private readonly Label storageSummary = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Label computerInfoStatus = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Label liveCpuValue = new() { AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold) };
    private readonly Label liveCpuDetail = new() { AutoSize = false, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), AutoEllipsis = true };
    private readonly Label liveMemoryValue = new() { AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold) };
    private readonly Label liveMemoryDetail = new() { AutoSize = false, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), AutoEllipsis = true };
    private readonly Label liveGpuValue = new() { AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold) };
    private readonly Label liveGpuDetail = new() { AutoSize = false, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), AutoEllipsis = true };
    private readonly Label liveTemperatureValue = new() { AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold) };
    private readonly Label liveTemperatureDetail = new() { AutoSize = false, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), AutoEllipsis = true };
    private readonly System.Windows.Forms.Timer systemMetricsTimer = new() { Interval = 2000 };
    private SystemInventorySnapshot? systemInventory;
    private bool liveMetricsBusy;
    private readonly CheckBox scheduleEnabled = new() { Text = "Включить расписание", AutoSize = true, ForeColor = TextMain, BackColor = Surface };
    private readonly ComboBox scheduleFrequency = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 190 };
    private readonly ComboBox scheduleWeekday = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 190 };
    private readonly DateTimePicker scheduleTime = new() { Format = DateTimePickerFormat.Custom, CustomFormat = "HH:mm", ShowUpDown = true, Width = 110 };
    private readonly Label schedulePreview = new() { AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold) };
    private readonly Label scheduleSaveStatus = new() { AutoSize = true, ForeColor = Green, Font = new Font("Segoe UI", 9F) };
    private readonly Label schedulerTaskStatus = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Button quickScanButton = new();
    private readonly Button fullScanButton = new();
    private readonly Button updateButton = new();
    private readonly Button appUpdateCheckButton = new();
    private readonly Button appUpdateInstallButton = new();
    private readonly CheckBox appUpdateAutoCheckToggle = new() { AutoSize = true, ForeColor = TextMain, BackColor = Surface };
    private readonly CheckBox appUpdateAutoDownloadToggle = new() { AutoSize = true, ForeColor = TextMain, BackColor = Surface };
    private readonly Label appUpdateStatusLabel = new() { AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 9F) };
    private readonly Label appUpdateDetailLabel = new() { AutoSize = true, MaximumSize = new Size(840, 0), ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F) };
    private readonly Panel appUpdateBanner = new() { Height = 72, Dock = DockStyle.Top, BackColor = Color.FromArgb(30, 92, 70), Padding = new Padding(16, 10, 16, 10), Margin = new Padding(0, 0, 0, 12), Visible = false };
    private readonly Label appUpdateBannerLabel = new() { AutoSize = false, ForeColor = Color.White, Font = new Font("Segoe UI Semibold", 10.5F, FontStyle.Bold) };
    private readonly Button appUpdateBannerButton = new() { Width = 170, Height = 38, Text = "Установить" };
    private readonly System.Windows.Forms.Timer appUpdateTimer = new() { Interval = 6 * 60 * 60 * 1000 };
    private Button? scheduleSaveButton;
    private Button? quarantineAddButton;
    private Button? localAnalyzeButton;
    private Button? addResultBlacklistButton;
    private Button? addResultWhitelistButton;
    private Button? quarantineAnalysisButton;
    private Button? addManualRuleButton;
    private Button? removeFileRuleButton;
    private Button? installSelfProtectionButton;
    private Button? disableSelfProtectionButton;
    private Button? heuristicStartupButton;
    private Button? heuristicProcessesButton;
    private Label? protectionValue;
    private Label? signatureValue;
    private Label? lastScanValue;
    private Label? firewallValue;
    private Label? selfProtectionValue;
    private Label? monitorValue;
    private Label? restoreValue;
    private Label? diskValue;
    private Label? heuristicValue;
    private Label? securityCenterStatus;
    private Label? systemScanValue;
    private SystemScanReport? lastSystemScanReport;
    private SystemScanNetworkSnapshot? lastSystemScanNetwork;
    private IReadOnlyList<ProcessContextSnapshot> lastProcessContexts = Array.Empty<ProcessContextSnapshot>();
    private List<SystemScanReportSnapshot> scanReportHistory = [];
    private ProcessMonitorService? processMonitor;
    private bool changingMonitorToggle;
    private bool changingRestorePointToggle;
    private bool restorePointBeforeScans = true;
    private bool quarantineBusy;
    private bool heuristicBusy;
    private int heuristicRealtimeSignals;
    private string lastHeuristicScope = "Ожидает запуска";
    private int lastHeuristicExamined;
    private int lastHeuristicUnreadable;
    private DateTime? lastHeuristicAt;
    private ScheduleSettings currentSchedule = new(false, "Ежедневно", "09:00", "Понедельник");
    private bool busy;
    private bool selfProtectionRunning;
    private bool selfProtectionOperationBusy;
    private int navButtonIndex;
    private bool cleanupRowsUpdating;
    private bool systemInventoryBusy;
    private AppUpdateSettings appUpdateSettings = new(true, true);
    private AppUpdateManifest? pendingAppUpdate;
    private string? pendingAppUpdatePath;
    private string? pendingAppUpdateSha256;
    private bool appUpdateBusy;

    public MainForm()
    {
        Text = "DefenderGuard — панель Microsoft Defender";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(1020, 680);
        Size = new Size(1260, 820);
        BackColor = Background;
        ForeColor = TextMain;
        Font = new Font("Segoe UI", 9.5F);
        DoubleBuffered = true;
        Directory.CreateDirectory(AppData);
        restorePointBeforeScans = RestorePointPolicyStore.Load().Enabled;
        currentSchedule = LoadSchedule();
        appUpdateSettings = AppUpdateSettingsStore.Load();
        scanReportHistory = ScanReportStore.Load().ToList();
        lastSystemScanReport = scanReportHistory.FirstOrDefault() is { } storedReport
            ? ScanReportSnapshotMapper.ToReport(storedReport)
            : null;
        lastSystemScanNetwork = scanReportHistory.FirstOrDefault()?.Network;
        lastProcessContexts = scanReportHistory.FirstOrDefault()?.ProcessContexts ?? Array.Empty<ProcessContextSnapshot>();
        BuildShell();
        BuildHomePage();
        BuildReportPage();
        BuildHeuristicPage();
        BuildNetworkPage();
        BuildFileAnalysisPage();
        BuildQuarantinePage();
        RefreshQuarantine();
        BuildHistoryPage();
        BuildCleanupPage();
        BuildSettingsPage();
        RestorePendingAppUpdate();
        BuildSchedulePage();
        BuildStoragePage();
        BuildComputerInfoPage();
        AddEvent("Запущена оболочка Microsoft Defender.");
        RefreshHistory();
        FormClosing += (_, e) =>
        {
            if (quarantineBusy && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                MessageBox.Show(this, "Дождитесь завершения операции с карантином, чтобы сохранить целостность файла и его резервной копии.", "Операция выполняется", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            if (!e.Cancel && e.CloseReason == CloseReason.UserClosing && selfProtectionRunning && SelfProtectionManager.IsCurrentExecutableProtected && SelfProtectionManager.GetStatus().Running)
            {
                e.Cancel = true;
                MessageBox.Show(this, "Служба самозащиты автоматически перезапустит интерфейс после закрытия. Чтобы выйти, отключите самозащиту в «Параметры»; Windows запросит подтверждение UAC.", "Самозащита активна", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        };
        systemMetricsTimer.Tick += async (_, _) => await RefreshLiveMetricsAsync();
        appUpdateTimer.Tick += async (_, _) => await CheckForAppUpdateAsync(userInitiated: false);
        if (appUpdateSettings.AutoCheck) appUpdateTimer.Start();
        FormClosed += (_, _) =>
        {
            StopProcessMonitor();
            networkTimer.Stop();
            systemMetricsTimer.Stop();
            appUpdateTimer.Stop();
            dnsMonitor.Dispose();
        };
        Shown += async (_, _) =>
        {
            await RefreshSecurityCenterAsync();
            await RefreshTaskStatusAsync();
            await RefreshSelfProtectionStatusAsync();
            _ = CheckForAppUpdateAsync(userInitiated: false);
        };
    }

    private void BuildShell()
    {
        navButtonIndex = 0;
        sidebar.AutoScroll = true;
        var tagline = new Label { Text = "ПАНЕЛЬ MICROSOFT DEFENDER", AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 8F), Location = new Point(20, 20), Margin = new Padding(2, 0, 0, 24) };
        sidebar.Controls.Add(tagline);
        sidebar.Controls.Add(NavButton("Центр безопасности", "◫", () => { _ = RefreshSecurityCenterAsync(); ShowPage(homePage); }));
        sidebar.Controls.Add(NavButton("Отчёт проверки", "✓", () => { _ = RefreshReportAsync(); ShowPage(reportPage); }));
        sidebar.Controls.Add(NavButton("Эвристика", "⌕", () => { RefreshHeuristicRows(); ShowPage(heuristicPage); }));
        sidebar.Controls.Add(NavButton("Сеть", "◎", () => ShowPage(networkPage)));
        sidebar.Controls.Add(NavButton("Анализ файлов", "▣", () => { RefreshFileRuleRows(); ShowPage(fileAnalysisPage); }));
        sidebar.Controls.Add(NavButton("Карантин файлов", "⬡", () => { RefreshQuarantine(); ShowPage(quarantinePage); }));
        sidebar.Controls.Add(NavButton("Очистка", "⌫", () => { ScanCleanupTargets(); ShowPage(cleanupPage); }));
        sidebar.Controls.Add(NavButton("Журнал событий", "≡", () => { RefreshHistory(); ShowPage(historyPage); }));
        sidebar.Controls.Add(NavButton("Параметры", "⚙", () => { _ = RefreshSelfProtectionStatusAsync(); ShowPage(settingsPage); }));
        sidebar.Controls.Add(NavButton("Расписание проверок", "◷", () => ShowPage(schedulePage)));
        sidebar.Controls.Add(NavButton("Диски", "▤", () => { _ = RefreshSystemInventoryAsync(); ShowPage(storagePage); }));
        sidebar.Controls.Add(NavButton("Характеристики ПК", "▦", () => { _ = RefreshSystemInventoryAsync(); ShowPage(computerInfoPage); }));
        var spacer = new Panel { Height = 1, Dock = DockStyle.Bottom, Margin = new Padding(0) };
        sidebar.Controls.Add(spacer);
        var disclaimer = new Label { Text = "ДВИЖОК: DEFENDER\nСканирование и сигнатуры\nРеальное время — служба Windows", AutoSize = true, ForeColor = Green, Font = new Font("Segoe UI", 8.5F), Dock = DockStyle.Bottom, Padding = new Padding(0, 12, 0, 6) };
        sidebar.Controls.Add(disclaimer);
        Controls.Add(content);
        Controls.Add(sidebar);
        content.Controls.Add(pages);
        pages.Controls.Add(settingsPage);
        pages.Controls.Add(reportPage);
        pages.Controls.Add(networkPage);
        pages.Controls.Add(fileAnalysisPage);
        pages.Controls.Add(heuristicPage);
        pages.Controls.Add(historyPage);
        pages.Controls.Add(quarantinePage);
        pages.Controls.Add(cleanupPage);
        pages.Controls.Add(schedulePage);
        pages.Controls.Add(storagePage);
        pages.Controls.Add(computerInfoPage);
        pages.Controls.Add(homePage);
    }

    private Button NavButton(string title, string icon, Action click)
    {
        var button = new Button { Text = $"  {icon}     {title}", Height = 43, Width = 200, TextAlign = ContentAlignment.MiddleLeft, FlatStyle = FlatStyle.Flat, BackColor = Color.Transparent, ForeColor = TextMuted, Font = new Font("Segoe UI", 9.5F), Cursor = Cursors.Hand, Margin = new Padding(0, 2, 0, 4), Location = new Point(14, 54 + navButtonIndex * 49) };
        navButtonIndex++;
        button.FlatAppearance.BorderSize = 0;
        button.FlatAppearance.MouseOverBackColor = SurfaceAlt;
        button.Click += (_, _) => click();
        return button;
    }

    private void ShowPage(Control page)
    {
        foreach (Control child in pages.Controls) child.Visible = false;
        page.Visible = true;
        page.BringToFront();
        if (page == storagePage || page == computerInfoPage)
            _ = RefreshSystemInventoryAsync();

        if (page == computerInfoPage)
        {
            systemMetricsTimer.Start();
            _ = RefreshLiveMetricsAsync();
        }
        else
            systemMetricsTimer.Stop();

        if (page == networkPage)
        {
            _ = RefreshNetworkPageAsync(loadFirewallInventory: true);
            if (networkAutoRefresh.Checked) networkTimer.Start();
            if (dnsMonitorToggle.Checked) StartDnsMonitoring();
        }
        else
        {
            networkTimer.Stop();
            dnsMonitor.Stop();
        }
    }

    private void BuildHomePage()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1, RowCount = 10, BackColor = Background, Padding = new Padding(0) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < 10; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(Header("Центр безопасности", "Microsoft Defender, проверка автозагрузки и мониторинг запусков процессов."), 0, 0);

        var hero = new Panel { Height = 142, Dock = DockStyle.Top, BackColor = Color.FromArgb(21, 57, 54), Padding = new Padding(22), Margin = new Padding(0, 16, 0, 14) };
        var shield = new Label { Text = "✓", AutoSize = true, Font = new Font("Segoe UI", 30F, FontStyle.Bold), ForeColor = Green, Location = new Point(20, 35) };
        var heroTitle = new Label { Text = "Используется системный движок Microsoft Defender", AutoSize = true, Font = new Font("Segoe UI Semibold", 15F, FontStyle.Bold), ForeColor = TextMain, Location = new Point(82, 24) };
        var heroText = new Label { Text = "Проверки и обновления выполняет установленный Defender; защиту в реальном времени обеспечивает служба Windows. Приложение не содержит собственного антивирусного движка.", AutoSize = false, Width = 650, Height = 52, Font = new Font("Segoe UI", 9.5F), ForeColor = Color.FromArgb(187, 214, 207), Location = new Point(83, 59) };
        hero.Controls.AddRange([shield, heroTitle, heroText]);
        layout.Controls.Add(hero, 0, 1);

        var cards = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 104, WrapContents = false, BackColor = Background, Margin = new Padding(0, 0, 0, 14) };
        var protectionCard = (Panel)StatCard("ЗАЩИТА В РЕАЛЬНОМ ВРЕМЕНИ", "Проверка…", "Microsoft Defender", Green);
        protectionValue = protectionCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        cards.Controls.Add(protectionCard);
        var signatureCard = (Panel)StatCard("СИГНАТУРЫ DEFENDER", "Проверка…", "версия и дата обновления", Amber);
        signatureValue = signatureCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        cards.Controls.Add(signatureCard);
        var lastScanCard = (Panel)StatCard("ПОСЛЕДНЯЯ ПРОВЕРКА", LastScanText(), "по данным Microsoft Defender", TextMain);
        lastScanValue = lastScanCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        cards.Controls.Add(lastScanCard);
        var persistedScanText = lastSystemScanReport is null ? "Не запускалась" : lastSystemScanReport.FinishedAt.ToString("dd.MM HH:mm");
        var persistedScanColor = lastSystemScanReport is null ? TextMuted : lastSystemScanReport.DefenderExitCode == 0 && lastSystemScanReport.HighSignals == 0 ? Green : Amber;
        var persistedScanDetail = lastSystemScanReport is null ? "Defender + эвристика + процессы" : $"сигналов: {lastSystemScanReport.HighSignals + lastSystemScanReport.MediumSignals:N0}; отчёт сохранён";
        var systemScanCard = (Panel)StatCard("ПОЛНАЯ ПРОВЕРКА СИСТЕМЫ", persistedScanText, persistedScanDetail, persistedScanColor);
        systemScanValue = systemScanCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        cards.Controls.Add(systemScanCard);
        layout.Controls.Add(cards, 0, 2);

        var componentTitle = new Panel { Height = 40, Dock = DockStyle.Top, BackColor = Background, Margin = new Padding(0, 0, 0, 4) };
        componentTitle.Controls.Add(new Label { Text = "Состояние компонентов", AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 12F, FontStyle.Bold), Location = new Point(0, 7) });
        var refreshCenterButton = MakeButton("Обновить", SurfaceAlt, TextMain, 125, RefreshSecurityCenterAsync);
        refreshCenterButton.Location = new Point(865, 0);
        componentTitle.Controls.Add(refreshCenterButton);
        securityCenterStatus = new Label { AutoSize = false, Width = 780, Height = 22, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), Location = new Point(170, 9), AutoEllipsis = true };
        componentTitle.Controls.Add(securityCenterStatus);
        layout.Controls.Add(componentTitle, 0, 3);

        var componentCards = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 190, WrapContents = true, BackColor = Background, Margin = new Padding(0, 0, 0, 12) };
        var firewallCard = (Panel)StatCard("WINDOWS FIREWALL", "Проверка…", "профили и правила", Green);
        firewallValue = firewallCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        componentCards.Controls.Add(firewallCard);
        var selfCard = (Panel)StatCard("САМОЗАЩИТА", "Проверка…", "служба DefenderGuard", TextMuted);
        selfProtectionValue = selfCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        componentCards.Controls.Add(selfCard);
        var monitorCard = (Panel)StatCard("МОНИТОР ПРОЦЕССОВ", "Выключен", "новые запуски", TextMuted);
        monitorValue = monitorCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        componentCards.Controls.Add(monitorCard);
        var restoreCard = (Panel)StatCard("ТОЧКА ВОССТАНОВЛЕНИЯ", "Проверка…", "политика перед операциями", TextMuted);
        restoreValue = restoreCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        componentCards.Controls.Add(restoreCard);
        var heuristicCard = (Panel)StatCard("ЭВРИСТИЧЕСКИЕ СИГНАЛЫ", heuristicFindings.Count.ToString("N0"), "в текущей сессии", Amber);
        heuristicValue = heuristicCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        componentCards.Controls.Add(heuristicCard);
        var diskCard = (Panel)StatCard("СВОБОДНОЕ МЕСТО", "Проверка…", "системный диск", Green);
        diskValue = diskCard.Controls.OfType<Label>().FirstOrDefault(label => label.Location.Y == 27);
        componentCards.Controls.Add(diskCard);
        layout.Controls.Add(componentCards, 0, 4);

        var actionTitle = new Label { Text = "Запустить проверку", AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 12F, FontStyle.Bold), Margin = new Padding(0, 4, 0, 8) };
        layout.Controls.Add(actionTitle, 0, 5);
        var actions = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 180, WrapContents = true, BackColor = Background };
        fullSystemScanButton.Text = "  Полная проверка системы";
        StyleButton(fullSystemScanButton, Green, Color.FromArgb(8, 27, 23));
        fullSystemScanButton.Width = 205;
        fullSystemScanButton.Click += async (_, _) => await RunFullSystemScanAsync();

        quickScanButton.Text = "  Быстрая проверка";
        StyleButton(quickScanButton, Green, Color.FromArgb(8, 27, 23));
        quickScanButton.Width = 170;
        quickScanButton.Click += async (_, _) => await RunDefenderAction("Быстрая проверка Microsoft Defender", () => DefenderClient.QuickScan());
        fullScanButton.Text = "Полная проверка";
        StyleButton(fullScanButton, SurfaceAlt, TextMain);
        fullScanButton.Width = 150;
        fullScanButton.Click += async (_, _) => await RunDefenderAction("Полная проверка Microsoft Defender", () => DefenderClient.FullScan());
        var folderButton = MakeButton("Проверить папку", SurfaceAlt, TextMain, 145, async () => await ChooseFolder());
        var filesButton = MakeButton("Выбрать файлы", SurfaceAlt, TextMain, 140, async () => await ChooseFiles());
        updateButton.Text = "Обновить базы";
        StyleButton(updateButton, Color.FromArgb(38, 57, 78), TextMain);
        updateButton.Width = 145;
        updateButton.Click += async (_, _) => await RunDefenderAction("Обновление баз Microsoft Defender", () => DefenderClient.UpdateSignatures(), isScan: false);
        var testButton = MakeButton("Создать тест EICAR", Color.FromArgb(57, 48, 30), Amber, 150, () => CreateTestFile());
        var usbButton = MakeButton("Проверить USB", SurfaceAlt, TextMain, 145, async () => await ScanUsbDrives());
        var startupButton = MakeButton("Проверить автозагрузку", SurfaceAlt, TextMain, 185, async () => await RunDefenderAction("Проверка стандартных точек автозагрузки", WindowsStartupScanner.Scan));
        var processesButton = MakeButton("Проверить активные процессы", SurfaceAlt, TextMain, 210, async () => await RunDefenderAction("Проверка файлов образов активных процессов", ActiveProcessScanner.Scan));
        actions.Controls.AddRange([fullSystemScanButton, quickScanButton, fullScanButton, folderButton, filesButton, usbButton, startupButton, processesButton, updateButton, testButton]);
        layout.Controls.Add(actions, 0, 6);

        var monitorPanel = new Panel { Dock = DockStyle.Top, Height = 58, BackColor = Background, Margin = new Padding(0, 2, 0, 4) };
        processMonitorToggle.Location = new Point(0, 1);
        processMonitorToggle.CheckedChanged += (_, _) => ToggleProcessMonitor();
        processMonitorStatus.Text = "Мониторинг выключен. Включите флажок, чтобы отслеживать запуски и проверять файлы образов Defender.";
        processMonitorStatus.Location = new Point(2, 30);
        processMonitorStatus.Width = 720;
        processMonitorStatus.Height = 22;
        monitorPanel.Controls.Add(processMonitorToggle);
        monitorPanel.Controls.Add(processMonitorStatus);
        layout.Controls.Add(monitorPanel, 0, 7);

        var statusLinePanel = new Panel { Height = 31, Dock = DockStyle.Top, BackColor = Background, Padding = new Padding(2, 5, 0, 0) };
        statusLine.Text = "Microsoft Defender: проверяю состояние защиты…";
        progress.Dock = DockStyle.None;
        progress.Location = new Point(0, 22);
        progress.Width = 380;
        statusLinePanel.Controls.Add(statusLine);
        statusLinePanel.Controls.Add(progress);
        layout.Controls.Add(statusLinePanel, 0, 8);

        var threatCard = new Panel { Height = 270, Dock = DockStyle.Top, BackColor = Surface, Padding = new Padding(16), Margin = new Padding(0, 5, 0, 8) };
        var threatHeader = new Panel { Dock = DockStyle.Top, Height = 35, BackColor = Surface };
        threatHeader.Controls.Add(new Label { Text = "Результаты текущей сессии", AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 11F, FontStyle.Bold), Location = new Point(0, 2) });
        threatHeader.Controls.Add(new Label { Text = "Подробности угроз — в «Истории защиты» Windows", AutoSize = true, ForeColor = TextMuted, Anchor = AnchorStyles.Top | AnchorStyles.Right, Location = new Point(510, 5) });
        detections.Padding = new Padding(0, 3, 0, 3);
        threatCard.Controls.Add(detections);
        threatCard.Controls.Add(threatHeader);
        layout.Controls.Add(threatCard, 0, 9);
        ConfigureAppUpdateBanner();
        homePage.Controls.Add(layout);
    }

    private void BuildReportPage()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Background };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 72));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(Header("Отчёт проверки", "Единый экран результатов: Microsoft Defender, автозагрузка, процессы, сеть и локальный карантин."), 0, 0);

        var toolbar = new Panel { Dock = DockStyle.Fill, BackColor = Surface, Padding = new Padding(10, 8, 10, 8) };
        var refresh = MakeButton("Обновить отчёт", SurfaceAlt, TextMain, 155, RefreshReportAsync);
        refresh.Location = new Point(10, 8);
        var home = MakeButton("К центру безопасности", SurfaceAlt, TextMain, 185, () => ShowPage(homePage));
        home.Location = new Point(174, 8);
        reportStatus.Location = new Point(370, 17);
        toolbar.Controls.AddRange([refresh, home, reportStatus]);
        layout.Controls.Add(toolbar, 0, 1);

        layout.Controls.Add(reportRows, 0, 2);
        reportPage.Controls.Add(layout);
    }

    private async Task RefreshReportAsync()
    {
        if (IsDisposed) return;
        reportStatus.Text = "Собираю актуальные данные для отчёта…";
        reportStatus.ForeColor = TextMuted;
        try
        {
            var defenderTask = Task.Run(() =>
            {
                try
                {
                    var status = DefenderClient.GetStatus();
                    return (Available: true, Error: "", AntivirusEnabled: status.AntivirusEnabled, RealTimeProtectionEnabled: status.RealTimeProtectionEnabled,
                        SignatureVersion: status.SignatureVersion ?? "", SignatureUpdated: status.SignatureUpdated ?? "",
                        QuickScanEndTime: status.QuickScanEndTime ?? "", FullScanEndTime: status.FullScanEndTime ?? "");
                }
                catch (Exception ex)
                {
                    return (Available: false, Error: ex.Message, AntivirusEnabled: false, RealTimeProtectionEnabled: false,
                        SignatureVersion: "", SignatureUpdated: "", QuickScanEndTime: "", FullScanEndTime: "");
                }
            });
            var networkTask = Task.Run(() =>
            {
                try
                {
                    return (Available: true, Error: "", Connections: NetworkConnectionReader.Read());
                }
                catch (Exception ex)
                {
                    return (Available: false, Error: ex.Message, Connections: Array.Empty<TcpConnectionSnapshot>());
                }
            });
            await Task.WhenAll(defenderTask, networkTask);

            var defender = await defenderTask;
            var network = await networkTask;
            if (network.Available)
                networkConnections = network.Connections;
            var connections = network.Connections;
            var quarantine = LoadQuarantine();
            var missingQuarantine = quarantine.Count(item => !File.Exists(item.StoredPath));
            reportRefreshedAt = DateTime.Now;

            reportRows.SuspendLayout();
            reportRows.Controls.Clear();

            var defenderHealthy = defender.Available && defender.AntivirusEnabled && defender.RealTimeProtectionEnabled;
            var latestDefenderScan = defender.Available
                ? LatestScan(defender.QuickScanEndTime, defender.FullScanEndTime)
                : "нет данных";
            var fullSystemText = lastSystemScanReport is null
                ? "Комплексная проверка ещё не запускалась."
                : $"{lastSystemScanReport.FinishedAt:dd.MM.yyyy HH:mm:ss} · Defender код {lastSystemScanReport.DefenderExitCode} · высоких сигналов {lastSystemScanReport.HighSignals}";

            AddReportCard(
                "КОМПЛЕКСНАЯ ПРОВЕРКА",
                fullSystemText,
                lastSystemScanReport is null
                    ? "Запускается кнопкой «Полная проверка системы» в Центре безопасности. Эта проверка не выполняется автоматически при открытии отчёта."
                    : $"Автозагрузка: {lastSystemScanReport.StartupExamined:N0} объектов / сигналов {lastSystemScanReport.StartupFindings:N0}. Процессы: {lastSystemScanReport.ProcessExamined:N0} образов / сигналов {lastSystemScanReport.ProcessFindings:N0}. Сетевой снимок: {lastSystemScanNetwork?.TcpConnections.Count ?? 0:N0} TCP, {lastSystemScanNetwork?.DnsEvents.Count ?? 0:N0} DNS событий.",
                lastSystemScanReport is null ? TextMuted : (lastSystemScanReport.DefenderExitCode == 0 && lastSystemScanReport.HighSignals == 0 ? Green : Amber),
                "К проверке",
                () => ShowPage(homePage));

            AddReportCard(
                "MICROSOFT DEFENDER",
                defender.Available ? (defenderHealthy ? "Защита активна" : "Проверьте состояние") : "Данные недоступны",
                defender.Available
                    ? $"Сигнатуры: {(string.IsNullOrWhiteSpace(defender.SignatureVersion) ? "нет данных" : defender.SignatureVersion)} · обновлено: {(string.IsNullOrWhiteSpace(defender.SignatureUpdated) ? "нет данных" : defender.SignatureUpdated)} · последняя проверка: {latestDefenderScan}."
                    : $"Не удалось получить статус Defender: {defender.Error}",
                defenderHealthy ? Green : Amber,
                "Центр безопасности",
                () => { _ = RefreshSecurityCenterAsync(); ShowPage(homePage); });

            var startupText = lastSystemScanReport is null
                ? "Нет результата"
                : $"Сигналов {lastSystemScanReport.StartupFindings:N0}";
            var startupDetail = lastSystemScanReport is null
                ? "Раздел показывает результаты последней комплексной проверки после её запуска."
                : $"Просмотрено {lastSystemScanReport.StartupExamined:N0}; недоступно {lastSystemScanReport.StartupUnreadable:N0}. Сигналы приведены в общей эвристической ленте.";
            AddReportCard("АВТОЗАПУСК", startupText, startupDetail, lastSystemScanReport?.StartupFindings > 0 ? Amber : TextMuted, "Открыть эвристику", () => { RefreshHeuristicRows(); ShowPage(heuristicPage); });

            var processText = lastSystemScanReport is null
                ? "Нет результата"
                : $"Сигналов {lastSystemScanReport.ProcessFindings:N0}";
            var processDetail = lastSystemScanReport is null
                ? "Результат появится после комплексной проверки."
                : $"Просмотрено {lastSystemScanReport.ProcessExamined:N0} образов; недоступно {lastSystemScanReport.ProcessUnreadable:N0}. Анализ использует пути образов и объяснимые эвристики.";
            AddReportCard("АКТИВНЫЕ ПРОЦЕССЫ", processText, processDetail, lastSystemScanReport?.ProcessFindings > 0 ? Amber : TextMuted, "Открыть эвристику", () => { RefreshHeuristicRows(); ShowPage(heuristicPage); });

            var highNetwork = connections.Count(row => row.RiskScore >= 4);
            var enabledProfiles = firewallProfiles.Count(profile => profile.Enabled);
            var firewallText = firewallProfiles.Count == 0 ? "нет данных" : $"{enabledProfiles}/{firewallProfiles.Count} профиля Firewall";
            var networkError = network.Available ? "" : $" Ошибка чтения TCP: {network.Error}.";
            AddReportCard(
                "СЕТЬ",
                $"{connections.Count:N0} TCP · {udpEndpoints.Count:N0} UDP",
                $"{firewallText} · правил DefenderGuard: {managedNetworkRules.Count} · повышенных TCP-сигналов: {highNetwork:N0}.{networkError} IP/порт/процесс доступны для локального контекста; содержимое пакетов не анализируется.",
                highNetwork > 0 || firewallProfiles.Any(profile => !profile.Enabled) || !network.Available ? Amber : Green,
                "Открыть сеть",
                () => ShowPage(networkPage));

            AddReportCard(
                "КАРАНТИН",
                quarantine.Count == 0 ? "Пуст" : $"{quarantine.Count:N0} записей",
                missingQuarantine == 0
                    ? "Локальные записи доступны. Восстановление повторно проверяет сохранённый файл Microsoft Defender."
                    : $"У {missingQuarantine:N0} записей отсутствует сохранённый файл; проверьте Историю защиты Windows.",
                missingQuarantine > 0 ? Amber : (quarantine.Count == 0 ? TextMuted : Green),
                "Открыть карантин",
                () => { RefreshQuarantine(); ShowPage(quarantinePage); });

            var findings = heuristicFindings.Count > 0
                ? heuristicFindings.OrderByDescending(item => item.ObservedAt).Take(6).ToArray()
                : (scanReportHistory.FirstOrDefault()?.Findings ?? Array.Empty<ScanReportFindingSnapshot>())
                    .Select(ScanReportSnapshotMapper.ToFinding)
                    .OrderByDescending(item => item.ObservedAt)
                    .Take(6)
                    .ToArray();
            var signalCard = new Panel { Width = Math.Max(900, reportRows.ClientSize.Width - 28), Height = Math.Max(110, 78 + findings.Length * 62), BackColor = Surface, Padding = new Padding(14), Margin = new Padding(0, 0, 0, 10) };
            signalCard.Controls.Add(new Label { Text = "ПОСЛЕДНИЕ ЭВРИСТИЧЕСКИЕ СИГНАЛЫ", AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 10.5F, FontStyle.Bold), Location = new Point(14, 10) });
            if (findings.Length == 0)
            {
                signalCard.Controls.Add(new Label
                {
                    Text = scanReportHistory.Count == 0
                        ? "Сохранённых сигналов пока нет. Это не является доказательством отсутствия угроз."
                        : "Сигналов в текущей сессии нет; выше показаны последние сохранённые результаты. Это не является доказательством отсутствия угроз.",
                    AutoSize = true,
                    ForeColor = TextMuted,
                    Location = new Point(15, 40)
                });
            }
            else
            {
                var y = 40;
                foreach (var finding in findings)
                {
                    var riskColor = finding.Risk == HeuristicRisk.High ? Color.FromArgb(242, 104, 104) : finding.Risk == HeuristicRisk.Medium ? Amber : TextMuted;
                    var line = new Label { Text = $"{RiskText(finding.Risk).ToUpperInvariant()} · {finding.Source} · {finding.Subject}", AutoEllipsis = true, Width = signalCard.Width - 190, Height = 22, ForeColor = riskColor, Location = new Point(15, y) };
                    var open = new Button { Text = "Открыть сигнал", Width = 145, Height = 32, Location = new Point(signalCard.Width - 160, y - 5), Tag = finding };
                    StyleButton(open, SurfaceAlt, TextMain);
                    open.Click += (_, _) => OpenHeuristicFinding((HeuristicFinding)open.Tag!);
                    signalCard.Controls.AddRange([line, open]);
                    y += 62;
                }
            }
            if (scanReportHistory.Count > 0)
            {
                var historyHeader = new Panel { Width = Math.Max(900, reportRows.ClientSize.Width - 28), Height = 48, BackColor = Background, Margin = new Padding(0, 6, 0, 0) };
                historyHeader.Controls.Add(new Label { Text = "СОХРАНЁННАЯ ИСТОРИЯ ПРОВЕРОК", AutoSize = true, ForeColor = TextMain, Font = new Font("Segoe UI Semibold", 11F, FontStyle.Bold), Location = new Point(0, 6) });
                historyHeader.Controls.Add(new Label { Text = $"Последние {Math.Min(scanReportHistory.Count, 10)} комплексных проверок", AutoSize = true, ForeColor = TextMuted, Location = new Point(0, 28) });
                reportRows.Controls.Add(historyHeader);
                foreach (var stored in scanReportHistory.Take(10))
                {
                    var storedColor = stored.DefenderExitCode == 0 && stored.HighSignals == 0 ? Green : Amber;
                    var storedNetwork = stored.Network is null
                        ? "Сетевой снимок отсутствует (старый формат отчёта)."
                        : $"Сеть: {stored.Network.TcpConnections.Count:N0} TCP · {stored.Network.DnsEvents.Count:N0} DNS событий · Firewall-профилей: {stored.Network.FirewallProfiles.Count:N0} · правил DefenderGuard: {stored.Network.FirewallRules.Count:N0}.";
                    AddReportCard(
                        "СОХРАНЁННАЯ ПРОВЕРКА",
                        stored.FinishedAt.ToString("dd.MM.yyyy HH:mm:ss"),
                        $"Defender: код {stored.DefenderExitCode} · автозагрузка: {stored.StartupFindings:N0} сигналов · процессы: {stored.ProcessFindings:N0} сигналов · всего сохранено объектов: {stored.Findings.Count:N0}. {storedNetwork}",
                        storedColor,
                        "Открыть детали",
                        () => OpenStoredSystemScanReport(stored));
                }
            }

            reportRows.Controls.Add(signalCard);

            reportRows.ResumeLayout();
            reportStatus.Text = $"Отчёт обновлён {reportRefreshedAt.Value:dd.MM.yyyy HH:mm:ss}. Данные локального состояния Windows; результаты Defender интерпретируются по его собственному коду и истории защиты.";
            reportStatus.ForeColor = TextMuted;
        }
        catch (Exception ex)
        {
            reportStatus.Text = "Не удалось полностью собрать отчёт: " + ex.Message;
            reportStatus.ForeColor = Amber;
            AddEvent("Ошибка обновления отчёта проверки: " + ex.Message);
        }
    }

    private void AddReportCard(string title, string value, string detail, Color accent, string buttonText, Action action)
    {
        var card = new Panel { Width = Math.Max(900, reportRows.ClientSize.Width - 28), Height = 104, BackColor = Surface, Padding = new Padding(14), Margin = new Padding(0, 0, 0, 10) };
        card.Controls.Add(new Label { Text = title, AutoSize = true, ForeColor = TextMuted, Font = new Font("Segoe UI", 8F), Location = new Point(14, 10) });
        card.Controls.Add(new Label { Text = value, AutoSize = false, AutoEllipsis = true, Width = card.Width - 250, Height = 24, ForeColor = accent, Font = new Font("Segoe UI Semibold", 13F, FontStyle.Bold), Location = new Point(14, 28) });
        card.Controls.Add(new Label { Text = detail, AutoEllipsis = true, Width = card.Width - 250, Height = 40, ForeColor = TextMuted, Font = new Font("Segoe UI", 8.5F), Location = new Point(15, 55) });
        var actionButton = MakeButton(buttonText, SurfaceAlt, TextMain, 205, action);
        actionButton.Location = new Point(card.Width - 220, 31);
        card.Controls.Add(actionButton);
        reportRows.Controls.Add(card);
    }

    private void OpenStoredSystemScanReport(SystemScanReportSnapshot snapshot)
    {
        using var dialog = new Form
        {
            Text = "Детали сохранённой проверки — DefenderGuard",
            StartPosition = FormStartPosition.CenterParent,
            Size = new Size(1060, 700),
            MinimumSize = new Size(900, 560),
            BackColor = Background,
            ForeColor = TextMain
        };

        var header = new Panel { Dock = DockStyle.Top, Height = 86, BackColor = Surface, Padding = new Padding(16) };
        header.Controls.Add(new Label
        {
            Text = $"Комплексная проверка · {snapshot.FinishedAt:dd.MM.yyyy HH:mm:ss}",
            AutoSize = true,
            ForeColor = TextMain,
            Font = new Font("Segoe UI Semibold", 15F, FontStyle.Bold),
            Location = new Point(16, 10)
        });
        header.Controls.Add(new Label
        {
            Text = $"Defender: код {snapshot.DefenderExitCode} · автозагрузка: {snapshot.StartupFindings:N0} сигналов · процессы: {snapshot.ProcessFindings:N0} сигналов · высоких: {snapshot.HighSignals:N0} · средних: {snapshot.MediumSignals:N0}",
            AutoSize = false,
            Width = 980,
            Height = 35,
            ForeColor = TextMuted,
            Location = new Point(16, 42)
        });
        dialog.Controls.Add(header);

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 112,
            BackColor = Surface,
            Padding = new Padding(10),
            WrapContents = true,
            AutoScroll = true
        };
        var actionStatus = new Label
        {
            AutoSize = false,
            Width = 1000,
            Height = 24,
            ForeColor = TextMuted,
            Text = "Выберите сохранённый сигнал; актуальный SHA-256 будет вычислен заново."
        };
        var openFile = new Button { Text = "Открыть файл", Width = 165, Enabled = false, Tag = null };
        var defender = new Button { Text = "Повторно проверить Defender", Width = 205, Enabled = false };
        var whitelist = new Button { Text = "Добавить SHA-256 в белый список", Width = 225, Enabled = false };
        var quarantine = new Button { Text = "Поместить в карантин", Width = 175, Enabled = false };
        var leave = new Button { Text = "Оставить без изменений", Width = 190, Enabled = false };
        var close = new Button { Text = "Закрыть", Width = 105 };
        StyleButton(openFile, SurfaceAlt, TextMain);
        StyleButton(defender, Color.FromArgb(38, 57, 78), TextMain);
        StyleButton(whitelist, Color.FromArgb(38, 76, 62), TextMain);
        StyleButton(quarantine, Color.FromArgb(108, 48, 51), TextMain);
        StyleButton(leave, SurfaceAlt, TextMain);
        StyleButton(close, SurfaceAlt, TextMain);
        close.Click += (_, _) => dialog.Close();
        actions.Controls.Add(actionStatus);
        actions.Controls.AddRange([openFile, defender, whitelist, quarantine, leave, close]);
        dialog.Controls.Add(actions);

        var detail = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = SurfaceAlt,
            ForeColor = TextMain,
            BorderStyle = BorderStyle.None,
            Font = new Font("Segoe UI", 9F),
            Padding = new Padding(10)
        };
        var rows = new ListView
        {
            Dock = DockStyle.Left,
            Width = 520,
            View = View.Details,
            FullRowSelect = true,
            MultiSelect = false,
            HideSelection = false,
            BackColor = Surface,
            ForeColor = TextMain,
            BorderStyle = BorderStyle.None
        };
        rows.Columns.Add("Риск / источник", 185);
        rows.Columns.Add("Объект", 315);

        foreach (var finding in snapshot.Findings.OrderByDescending(item => item.Score).ThenByDescending(item => item.ObservedAt))
        {
            var risk = Enum.TryParse<HeuristicRisk>(finding.Risk, true, out var parsedRisk) ? parsedRisk : HeuristicRisk.Low;
            var item = new ListViewItem($"{RiskText(risk)} ({finding.Score})") { Tag = finding };
            item.SubItems.Add(finding.Subject);
            item.ForeColor = risk == HeuristicRisk.High ? Color.FromArgb(242, 104, 104) : risk == HeuristicRisk.Medium ? Amber : TextMain;
            rows.Items.Add(item);
        }

        ScanReportFindingSnapshot? selectedFinding = null;
        string? currentHash = null;
        var selectionVersion = 0;

        async Task RefreshStoredFindingAsync(ScanReportFindingSnapshot finding, int version)
        {
            var path = string.IsNullOrWhiteSpace(finding.FilePath) ? null : Path.GetFullPath(finding.FilePath);
            currentHash = null;
            actionStatus.ForeColor = TextMuted;
            actionStatus.Text = path is null
                ? "У этого сигнала нет конкретного файла; действия над файлом недоступны."
                : "Проверяю актуальное состояние файла и SHA-256…";
            openFile.Tag = path;
            openFile.Enabled = path is not null && File.Exists(path);
            defender.Enabled = false;
            whitelist.Enabled = false;
            quarantine.Enabled = false;
            leave.Enabled = true;

            if (path is null) return;

            try
            {
                var fresh = await Task.Run(() => ComputeRemediationSha256(path));
                if (version != selectionVersion || selectedFinding is null || !ReferenceEquals(selectedFinding, finding)) return;
                currentHash = fresh;
                actionStatus.ForeColor = Green;
                actionStatus.Text = "Актуальный SHA-256 подтверждён: " + fresh;
                openFile.Enabled = File.Exists(path);
                defender.Enabled = File.Exists(path);
                whitelist.Enabled = File.Exists(path);
                quarantine.Enabled = File.Exists(path);
                leave.Enabled = true;
                var lists = FileRuleStore.Load();
                var match = lists.Blacklist.Any(rule => rule.Sha256.Equals(fresh, StringComparison.OrdinalIgnoreCase))
                    ? "Совпадение: локальный чёрный список."
                    : lists.Whitelist.Any(rule => rule.Sha256.Equals(fresh, StringComparison.OrdinalIgnoreCase))
                        ? "Совпадение: локальный белый список."
                        : "Совпадения с локальными списками SHA-256 нет.";

                detail.Text =
                    $"Время сигнала: {finding.ObservedAt:dd.MM.yyyy HH:mm:ss}\r\n" +
                    $"Источник: {finding.Source}\r\n" +
                    $"Объект: {finding.Subject}\r\n" +
                    $"Риск: {RiskText(Enum.TryParse<HeuristicRisk>(finding.Risk, true, out var risk) ? risk : HeuristicRisk.Low)}\r\n" +
                    $"Баллы: {finding.Score}\r\n\r\n" +
                    "Причины:\r\n" +
                    string.Join("\r\n", finding.Reasons.Select(reason => "• " + reason)) +
                    $"\r\n\r\nАктуальный файл:\r\n{path}\r\nАктуальный SHA-256:\r\n{fresh}\r\n{match}";
            }
            catch (Exception ex)
            {
                if (version != selectionVersion) return;
                currentHash = null;
                actionStatus.ForeColor = Amber;
                actionStatus.Text = "Безопасное действие недоступно: " + ex.Message;
                detail.Text =
                    $"Время сигнала: {finding.ObservedAt:dd.MM.yyyy HH:mm:ss}\r\n" +
                    $"Источник: {finding.Source}\r\n" +
                    $"Объект: {finding.Subject}\r\n" +
                    $"Файл: {path}\r\n\r\n" +
                    "Актуальный SHA-256: не вычислен\r\nОшибка проверки: " + ex.Message;
            }
        }

        rows.SelectedIndexChanged += async (_, _) =>
        {
            selectionVersion++;
            if (rows.SelectedItems.Count == 0)
            {
                selectedFinding = null;
                currentHash = null;
                detail.Text = "Выберите сигнал слева.";
                openFile.Tag = null;
                openFile.Enabled = false;
                defender.Enabled = false;
                whitelist.Enabled = false;
                quarantine.Enabled = false;
                leave.Enabled = false;
                actionStatus.Text = "Выберите сохранённый сигнал.";
                return;
            }

            selectedFinding = (ScanReportFindingSnapshot)rows.SelectedItems[0].Tag!;
            var finding = selectedFinding;
            var version = selectionVersion;
            detail.Text =
                $"Время сигнала: {finding.ObservedAt:dd.MM.yyyy HH:mm:ss}\r\n" +
                $"Источник: {finding.Source}\r\n" +
                $"Объект: {finding.Subject}\r\n" +
                $"Риск: {RiskText(Enum.TryParse<HeuristicRisk>(finding.Risk, true, out var risk) ? risk : HeuristicRisk.Low)}\r\n" +
                $"Баллы: {finding.Score}\r\n\r\n" +
                "Актуальный SHA-256: вычисляется…\r\n\r\n" +
                "Причины:\r\n" +
                string.Join("\r\n", finding.Reasons.Select(reason => "• " + reason));
            await RefreshStoredFindingAsync(finding, version);
        };

        var actionHistoryRows = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            MultiSelect = false,