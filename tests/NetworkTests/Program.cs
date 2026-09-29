using System.Net;
using System.Text;
using System.Text.Json;
using DemoGuard;

static void Assert(bool condition, string message)
{
    if (!condition) throw new Exception("FAIL: " + message);
}

var loopback = NetworkTrafficAnalyzer.Analyze([
    new TcpConnectionRaw(10, "browser.exe", @"C:\Program Files\Browser\browser.exe", "192.168.1.5", 51000, "192.168.1.20", 443, "Established")
]).Single();
Assert(loopback.RiskScore == 0, "обычное локальное TCP-соединение не должно автоматически выглядеть угрозой");

var publicAddress = NetworkTrafficAnalyzer.Analyze([
    new TcpConnectionRaw(11, "browser.exe", @"C:\Program Files\Browser\browser.exe", "192.168.1.5", 51000, "8.8.8.8", 443, "Established")
]).Single();
Assert(publicAddress.RiskScore == 1 && publicAddress.RiskReasons.Contains("внешний IP"), "публичный IP должен быть только слабым контекстным сигналом");

var nonPublicRanges = NetworkTrafficAnalyzer.Analyze([
    new TcpConnectionRaw(11, "browser.exe", @"C:\Program Files\Browser\browser.exe", "192.168.1.5", 51000, "100.64.0.1", 443, "Established"),
    new TcpConnectionRaw(11, "browser.exe", @"C:\Program Files\Browser\browser.exe", "192.168.1.5", 51001, "203.0.113.1", 443, "Established"),
    new TcpConnectionRaw(11, "browser.exe", @"C:\Program Files\Browser\browser.exe", "192.168.1.5", 51002, "2001:db8::1", 443, "Established")
]);
Assert(nonPublicRanges.All(row => row.RiskScore == 0), "CGNAT and documentation address ranges must not be treated as public reputation signals");

var suspiciousContext = NetworkTrafficAnalyzer.Analyze([
    new TcpConnectionRaw(12, "tool.exe", @"C:\Users\tester\AppData\Local\Temp\tool.exe", "192.168.1.5", 50000, "8.8.4.4", 4444, "Established")
]).Single();
Assert(suspiciousContext.RiskScore >= 4 && suspiciousContext.RiskLevel == "Повышенный сигнал", "сочетание temp + внешний IP + необычный порт должно давать повышенный сигнал с объяснением");

var fanoutRows = Enumerable.Range(1, 41).Select(i => new TcpConnectionRaw(13, "sync.exe", @"C:\Program Files\Sync\sync.exe", "192.168.1.5", 51000 + i, $"198.51.{i / 250}.{i % 250 + 1}", 443, "Established")).ToArray();
var fanout = NetworkTrafficAnalyzer.Analyze(fanoutRows);
Assert(fanout.All(row => row.RiskReasons.Contains("различных удалённых IP")), "высокое число разных endpoint у процесса должно быть объяснимым сигналом");

var temporaryFile = Path.Combine(Path.GetTempPath(), "network-test-image.exe");
File.WriteAllText(temporaryFile, "test only; never executed");
try
{
    var sample = new TcpConnectionSnapshot(20, "sample.exe", temporaryFile, "192.168.1.5", 51234, "203.0.113.9", 443, "Established", 1, "Слабый сигнал", "Тестовый объект.");
    var outboundToken = NetworkFirewallManager.CreateAddPayload(sample, "Outbound");
    var outboundJson = Encoding.UTF8.GetString(Convert.FromBase64String(outboundToken));
    var outbound = JsonSerializer.Deserialize<NetworkFirewallRequest>(outboundJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
    Assert(outbound.Action == "add" && outbound.Direction == "Outbound" && outbound.RemotePort == 443 && outbound.LocalPort == 0, "исходящее правило должно привязываться к TCP destination port");
    Assert(outbound.Name == NetworkFirewallManager.GetRuleName(sample, "Outbound"), "сгенерированное имя должно совпадать с правилом для UI-дедупликации");
    Assert(outbound.ProgramPath == Path.GetFullPath(temporaryFile) && outbound.RemoteAddress == "203.0.113.9", "правило должно содержать только точный исполняемый файл и IP");

    var inboundToken = NetworkFirewallManager.CreateAddPayload(sample, "Inbound");
    var inbound = JsonSerializer.Deserialize<NetworkFirewallRequest>(Encoding.UTF8.GetString(Convert.FromBase64String(inboundToken)), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
    Assert(inbound.Direction == "Inbound" && inbound.LocalPort == 51234 && inbound.RemotePort == 0, "входящее правило должно привязываться к локальному порту приложения");
    Assert(inbound.Name != outbound.Name, "направления должны иметь разные уникальные правила");

    var rejectsLoopback = false;
    try { NetworkFirewallManager.CreateAddPayload(sample with { RemoteAddress = IPAddress.Loopback.ToString() }, "Outbound"); }
    catch (InvalidOperationException) { rejectsLoopback = true; }
    Assert(rejectsLoopback, "loopback нельзя преобразовать в сетевое правило блокировки");

    var rejectsMulticast = false;
    try { NetworkFirewallManager.CreateAddPayload(sample with { RemoteAddress = "224.0.0.1" }, "Outbound"); }
    catch (InvalidOperationException) { rejectsMulticast = true; }
    Assert(rejectsMulticast, "multicast нельзя преобразовать в правило блокировки");
}
finally { File.Delete(temporaryFile); }

var ordinaryUdp = NetworkMetadataAnalyzer.AnalyzeUdp([
    new UdpEndpointRaw(30, "dns.exe", @"C:\Program Files\Service\dns.exe", "0.0.0.0", 5353)
]).Single();
Assert(ordinaryUdp.RiskScore == 0 && ordinaryUdp.RiskReasons.Contains("не запись удалённого peer"), "обычный UDP endpoint должен отображаться без подозрительного сигнала и явно объяснять границы данных");

var unusualUdp = NetworkMetadataAnalyzer.AnalyzeUdp([
    new UdpEndpointRaw(31, "tool.exe", @"C:\Users\tester\AppData\Local\Temp\tool.exe", "0.0.0.0", 4444)
]).Single();
Assert(unusualUdp.RiskScore >= 4 && unusualUdp.RiskReasons.Contains("пользовательской") && unusualUdp.RiskReasons.Contains("4444"), "UDP из Temp на необычном порту должен иметь только объяснимый повышенный сигнал");

var ordinaryDns = NetworkMetadataAnalyzer.AnalyzeDns(DateTime.UtcNow, "example.com", "1", "93.184.216.34", "0", null);
Assert(ordinaryDns.RiskScore == 0 && ordinaryDns.ClientProcessId is null, "обычный A-запрос без клиентского PID не должен получать риск-сигнал");

var longDns = NetworkMetadataAnalyzer.AnalyzeDns(DateTime.UtcNow, new string('a', 52) + ".example.com", "TXT", "", "0", null);
Assert(longDns.RiskScore >= 2 && longDns.RiskReasons.Contains("длинная DNS-метка"), "чрезмерно длинная DNS label должна иметь объяснимую эвристику");

var unusualDnsType = NetworkMetadataAnalyzer.AnalyzeDns(DateTime.UtcNow, "example.com", "252", "", "0", null);
Assert(unusualDnsType.RiskScore >= 2 && unusualDnsType.RiskReasons.Contains("Необычный тип DNS-запроса"), "редкий numeric DNS QTYPE должен создавать сигнал без вердикта");

var textDnsType = NetworkMetadataAnalyzer.AnalyzeDns(DateTime.UtcNow, "example.com", "TKEY", "", "0", null);
Assert(textDnsType.RiskScore >= 2 && textDnsType.RiskReasons.Contains("Редкий тип DNS-запроса"), "редкий текстовый DNS QTYPE должен распознаваться");

if (!OperatingSystem.IsWindows())
{
    using var monitor = new DnsMonitorService();
    Assert(!monitor.Start() && monitor.Status.Contains("только в Windows"), "DNS EventLog monitor должен отказывать с понятным статусом вне Windows");
    var udpUnsupported = false;
    try { NetworkUdpReader.Read(); }
    catch (PlatformNotSupportedException) { udpUnsupported = true; }
    Assert(udpUnsupported, "UDP PowerShell snapshot должен явно обозначать Windows-only platform boundary");
}

Console.WriteLine("PASS: TCP risk tiers, explanations, fan-out, firewall payloads/validation, UDP endpoint limits and signals, DNS label/QTYPE heuristics.");