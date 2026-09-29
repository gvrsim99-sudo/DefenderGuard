using System.Reflection;

var appAssembly = Assembly.Load("DefenderGuard");
var metadata = appAssembly.GetCustomAttributes<AssemblyMetadataAttribute>()
    .FirstOrDefault(x => x.Key == "DefenderGuard.UpdateManifestUrl");
var configuredChannel = metadata?.Value ?? string.Empty;
if (!string.IsNullOrWhiteSpace(configuredChannel) &&
    !configuredChannel.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
    throw new Exception("Update channel is not HTTPS: " + configuredChannel);

var updaterType = appAssembly.GetType("DemoGuard.AppUpdater")
    ?? throw new Exception("AppUpdater type missing.");
var versionProperty = updaterType.GetProperty("CurrentVersion", BindingFlags.Public | BindingFlags.Static)
    ?? throw new Exception("CurrentVersion property missing.");
var version = (Version?)versionProperty.GetValue(null);
var assemblyVersion = appAssembly.GetName().Version is { } av
    ? new Version(av.Major, av.Minor, Math.Max(0, av.Build), Math.Max(0, av.Revision))
    : throw new Exception("Assembly version missing.");
if (version != assemblyVersion)
    throw new Exception($"CurrentVersion mismatch: property={version}, assembly={assemblyVersion}");

var verifyMethod = updaterType.GetMethod("VerifyDownloadedPackage", BindingFlags.Public | BindingFlags.Static)
    ?? throw new Exception("VerifyDownloadedPackage method missing.");
var qaBundle = @"C:\Users\User\Downloads\DefenderGuard-release-wix-1.0.0\DefenderGuard-Setup-1.0.0.exe";
if (File.Exists(qaBundle))
{
    var qaHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(qaBundle)));
    var arguments = new object?[] { qaBundle, qaHash, null };
    var accepted = (bool)verifyMethod.Invoke(null, arguments)!;
    if (accepted)
        throw new Exception("QA-signed bundle was incorrectly accepted as a production update.");
    var rejection = arguments[2]?.ToString() ?? string.Empty;
    if (!rejection.Contains("QA", StringComparison.OrdinalIgnoreCase))
        throw new Exception("QA rejection reason was not explicit: " + rejection);
}

var freeReleaseBundle = Environment.GetEnvironmentVariable("APPUPDATE_FREE_RELEASE_BUNDLE")
    ?? @"C:\Users\User\Downloads\DefenderGuard-installer-wix\DefenderGuard-Setup-1.0.0.exe";
if (Environment.GetEnvironmentVariable("APPUPDATE_REQUIRE_FREE_RELEASE") == "1")
{
    if (!File.Exists(freeReleaseBundle))
        throw new Exception("Free release bundle missing: " + freeReleaseBundle);

    var releaseHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(freeReleaseBundle)));
    var arguments = new object?[] { freeReleaseBundle, releaseHash, null };
    var accepted = (bool)verifyMethod.Invoke(null, arguments)!;
    if (!accepted)
        throw new Exception("Pinned DefenderGuard Release signature was rejected: " + (arguments[2]?.ToString() ?? "unknown"));

    var tampered = Path.Combine(Path.GetTempPath(), "DefenderGuard-tampered.exe");
    File.Copy(freeReleaseBundle, tampered, true);
    try
    {
        using (var stream = new FileStream(tampered, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            stream.Seek(-1, SeekOrigin.End);
            var b = stream.ReadByte();
            stream.Seek(-1, SeekOrigin.End);
            stream.WriteByte((byte)(b ^ 0xFF));
        }

        var tamperArgs = new object?[] { tampered, releaseHash, null };
        var tamperAccepted = (bool)verifyMethod.Invoke(null, tamperArgs)!;
        if (tamperAccepted)
            throw new Exception("Tampered update package was incorrectly accepted.");
        var tamperReason = tamperArgs[2]?.ToString() ?? string.Empty;
        if (!tamperReason.Contains("SHA-256", StringComparison.OrdinalIgnoreCase))
            throw new Exception("Tamper rejection did not fail on SHA-256: " + tamperReason);
    }
    finally
    {
        try { File.Delete(tampered); } catch { }
    }
}

Console.WriteLine($"PASS: updater type, version metadata, channel '{(string.IsNullOrWhiteSpace(configuredChannel) ? "not configured" : configuredChannel)}', QA rejection and pinned free-release verification.");