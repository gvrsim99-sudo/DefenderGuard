using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace DemoGuard;

internal sealed record AppUpdateManifest(
    string Version,
    string Url,
    string Sha256,
    long SizeBytes,
    string? ReleaseNotes);

internal sealed record AppUpdateResult(
    bool Success,
    bool UpdateAvailable,
    Version? Version,
    AppUpdateManifest? Manifest,
    string Message,
    string? DownloadedPath,
    string? Sha256);

internal sealed record AppUpdateSettings(
    bool AutoCheck,
    bool AutoDownload);

internal sealed record PendingAppUpdate(
    AppUpdateManifest Manifest,
    string DownloadedPath,
    string Sha256);

internal static class AppPendingUpdateStore
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DemoGuard",
        "update-pending.json");

    public static PendingAppUpdate? Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return null;
            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<PendingAppUpdate>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch { return null; }
    }

    public static void Save(PendingAppUpdate pending)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var json = JsonSerializer.Serialize(pending, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(FilePath, json);
    }

    public static void Clear()
    {
        try { if (File.Exists(FilePath)) File.Delete(FilePath); } catch { }
    }
}

internal static class UpdateChannel
{
    public static string ManifestUrl
    {
        get
        {
            const string key = "DefenderGuard.UpdateManifestUrl";
            return System.Reflection.Assembly.GetEntryAssembly()?
                .GetCustomAttributes(false)
                .OfType<System.Reflection.AssemblyMetadataAttribute>()
                .FirstOrDefault(a => string.Equals(a.Key, key, StringComparison.Ordinal))
                ?.Value ?? string.Empty;
        }
    }

    public const string UserAgent = "DefenderGuard-Updater/1.0";
    public const long MaxDownloadBytes = 512L * 1024L * 1024L;

    // Free production path: trust only our dedicated DefenderGuard Release certificate.
    // The private key never ships with the application and must remain on the build machine.
    public const string PinnedReleaseCertificateSha256 = "15BF23928F6D1E27E58CEE96A220DA4A72D6F1E2CE83B3B0B7F4101C3B646AB6";
}

internal static class AppUpdateSettingsStore
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "DemoGuard",
        "update-settings.json");

    public static AppUpdateSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath))
                return new(true, true);

            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<AppUpdateSettings>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? new(true, true);
        }
        catch
        {
            return new(true, true);
        }
    }

    public static void Save(AppUpdateSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(FilePath, json);
    }
}

internal static class AppUpdater
{
    private static readonly HttpClient Http = CreateHttpClient();

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(5)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UpdateChannel.UserAgent);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return client;
    }

    public static Version CurrentVersion
    {
        get
        {
            var value = typeof(AppUpdater).Assembly.GetName().Version;
            return value is null
                ? new Version(1, 0, 0)
                : new Version(value.Major, value.Minor, value.Build < 0 ? 0 : value.Build, value.Revision < 0 ? 0 : value.Revision);
        }
    }

    public static async Task<AppUpdateResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(UpdateChannel.ManifestUrl))
            return new(false, false, null, null, "Канал обновлений ещё не настроен для production.", null, null);

        if (!Uri.TryCreate(UpdateChannel.ManifestUrl, UriKind.Absolute, out var manifestUri) ||
            manifestUri.Scheme != Uri.UriSchemeHttps)
            return new(false, false, null, null, "Адрес канала обновлений должен использовать HTTPS.", null, null);

        try
        {
            using var response = await Http.GetAsync(manifestUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
                return new(false, false, null, null, $"Сервер обновлений вернул HTTP {(int)response.StatusCode}.", null, null);

            var finalUri = response.RequestMessage?.RequestUri;
            if (finalUri is null || finalUri.Scheme != Uri.UriSchemeHttps)
                return new(false, false, null, null, "Канал обновлений перенаправил запрос на небезопасный адрес.", null, null);

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var manifest = JsonSerializer.Deserialize<AppUpdateManifest>(json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            var validation = ValidateManifest(manifest);
            if (!validation.Success)
                return new(false, false, null, null, validation.Message, null, null);

            var remoteVersion = Version.Parse(manifest!.Version);
            if (remoteVersion <= CurrentVersion)
                return new(true, false, remoteVersion, manifest, $"Установлена последняя версия {CurrentVersion}.", null, null);

            return new(true, true, remoteVersion, manifest,
                $"Доступно обновление {remoteVersion}.", null, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new(false, false, null, null, "Не удалось проверить обновления: " + ex.Message, null, null);
        }
    }

    public static async Task<AppUpdateResult> DownloadAsync(
        AppUpdateManifest manifest,
        CancellationToken cancellationToken = default)
    {
        var validation = ValidateManifest(manifest);
        if (!validation.Success)
            return new(false, false, null, null, validation.Message, null, null);

        var updateDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DemoGuard",
            "Updates");
        Directory.CreateDirectory(updateDirectory);
        CleanupStaleDownloads(updateDirectory);

        var fileName = "DefenderGuard-Setup-" + manifest.Version + ".exe";
        foreach (var c in Path.GetInvalidFileNameChars())
            fileName = fileName.Replace(c, '_');

        var target = Path.Combine(updateDirectory, fileName);
        var temp = target + ".download";
        try
        {
            if (File.Exists(temp)) File.Delete(temp);
            using var response = await Http.GetAsync(new Uri(manifest.Url), HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
                return new(false, false, null, manifest, $"Не удалось скачать обновление: HTTP {(int)response.StatusCode}.", null, null);

            var finalUri = response.RequestMessage?.RequestUri;
            if (finalUri is null || finalUri.Scheme != Uri.UriSchemeHttps)
                return new(false, false, null, manifest, "Скачивание обновления завершилось на небезопасном URL.", null, null);

            var contentLength = response.Content.Headers.ContentLength;
            if (contentLength.HasValue && contentLength.Value > UpdateChannel.MaxDownloadBytes)
                return new(false, false, null, manifest, "Обновление превышает допустимый размер.", null, null);

            await using (var input = await response.Content.ReadAsStreamAsync(cancellationToken))
            await using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 128, FileOptions.SequentialScan))
            {
                var buffer = new byte[1024 * 128];
                long total = 0;
                while (true)
                {
                    var read = await input.ReadAsync(buffer, cancellationToken);
                    if (read == 0) break;
                    total += read;
                    if (total > UpdateChannel.MaxDownloadBytes)
                        throw new InvalidOperationException("Обновление превышает допустимый размер.");
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
            }

            var actualSize = new FileInfo(temp).Length;
            if (manifest.SizeBytes > 0 && actualSize != manifest.SizeBytes)
                throw new InvalidOperationException($"Размер файла не совпадает с manifest: {actualSize} вместо {manifest.SizeBytes} байт.");

            var hash = await ComputeSha256Async(temp, cancellationToken);
            if (!hash.Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("SHA-256 обновления не совпадает с manifest.");

            var signature = VerifyAuthenticode(temp);
            if (!signature.Success)
                throw new InvalidOperationException(signature.Message);

            File.Move(temp, target, true);

            return new(true, true, Version.Parse(manifest.Version), manifest,
                $"Обновление {manifest.Version} скачано и проверено.", target, hash);
        }
        catch (OperationCanceledException)
        {
            TryDelete(temp);
            throw;
        }
        catch (Exception ex)
        {
            TryDelete(temp);
            return new(false, true, Version.TryParse(manifest.Version, out var v) ? v : null, manifest,
                "Не удалось подготовить обновление: " + ex.Message, null, null);
        }
    }

    private static void CleanupStaleDownloads(string updateDirectory)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(updateDirectory, "*.download"))
            {
                var age = DateTime.UtcNow - File.GetLastWriteTimeUtc(file);
                if (age > TimeSpan.FromDays(2)) TryDelete(file);
            }
        }
        catch { }
    }

    public static bool VerifyDownloadedPackage(string path, string expectedSha256, out string message)
    {
        try
        {
            if (!File.Exists(path))
            {
                message = "Файл обновления не найден.";
                return false;
            }

            var hash = ComputeSha256Async(path, CancellationToken.None).GetAwaiter().GetResult();
            if (!hash.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                message = "SHA-256 скачанного файла изменился после проверки.";
                return false;
            }

            var signature = VerifyAuthenticode(path);
            message = signature.Message;
            return signature.Success;
        }
        catch (Exception ex)
        {
            message = "Не удалось повторно проверить обновление: " + ex.Message;
            return false;
        }
    }

    private static (bool Success, string Message) ValidateManifest(AppUpdateManifest? manifest)
    {
        if (manifest is null)
            return (false, "Manifest обновлений пуст или имеет неверный формат.");

        if (!Version.TryParse(manifest.Version, out var version) || version <= new Version(0, 0, 0))
            return (false, "Manifest содержит неверную версию.");

        if (!Uri.TryCreate(manifest.Url, UriKind.Absolute, out var packageUri) ||
            packageUri.Scheme != Uri.UriSchemeHttps)
            return (false, "URL обновления должен использовать HTTPS.");

        if (!packageUri.AbsolutePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return (false, "URL обновления должен вести на EXE installer.");

        if (manifest.SizeBytes <= 0 || manifest.SizeBytes > UpdateChannel.MaxDownloadBytes)
            return (false, "Manifest содержит недопустимый размер файла.");

        if (!System.Text.RegularExpressions.Regex.IsMatch(manifest.Sha256 ?? "", "^[0-9A-Fa-f]{64}$"))
            return (false, "Manifest содержит неверный SHA-256.");

        return (true, "OK");
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 128, FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    private static (bool Success, string Message) VerifyAuthenticode(string path)
    {
        var status = WinTrustVerify(path);
        try
        {
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            if (certificate.Subject.Contains("DefenderGuard Local QA", StringComparison.OrdinalIgnoreCase))
                return (false, "Файл подписан локальным QA-сертификатом, а не release-подписью.");

            var certificateSha256 = certificate.GetCertHashString(HashAlgorithmName.SHA256);
            var pinned = string.Equals(certificateSha256, UpdateChannel.PinnedReleaseCertificateSha256, StringComparison.OrdinalIgnoreCase);
            if (!pinned)
                return (false, $"Подпись выполнена неизвестным сертификатом: {certificate.Subject}.");

            if (status == 0)
                return (true, $"Подпись DefenderGuard проверена Windows Authenticode: {certificate.Subject}");

            // The free distribution key is self-signed and therefore not trusted by the Windows root store.
            // Accept only the specific DefenderGuard certificate and only the expected untrusted-root results.
            const uint CertEUntrustedRoot = 0x800B0109;
            const uint CertEUntrustedTestRoot = 0x800B010D;
            if (status == CertEUntrustedRoot || status == CertEUntrustedTestRoot)
                return (true, $"Подпись DefenderGuard проверена закреплённым release-сертификатом: {certificate.Subject}");

            return (false, $"Authenticode-проверка не пройдена. WinVerifyTrust=0x{status:X8}; signer={certificate.Subject}.");
        }
        catch (Exception ex)
        {
            return (false, "Не удалось прочитать сертификат подписи: " + ex.Message);
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private static uint WinTrustVerify(string path)
    {
        var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
        var filePath = Marshal.StringToCoTaskMemUni(path);
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath
        };
        var fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

        var trustData = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = 2,
            fdwRevocationChecks = 0,
            dwUnionChoice = 1,
            pFile = fileInfoPtr,
            dwStateAction = 1
        };

        try
        {
            var result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            trustData.dwStateAction = 2;
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            return result;
        }
        finally
        {
            Marshal.FreeCoTaskMem(fileInfoPtr);
            Marshal.FreeCoTaskMem(filePath);
        }
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint WinVerifyTrust(
        IntPtr hwnd,
        ref Guid pgActionID,
        ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}

internal static class UpdateInstallerRunner
{
    public static int Run(string installerPath, string expectedSha256)
    {
        try
        {
            var updateRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DemoGuard",
                "Updates");
            var fullPath = Path.GetFullPath(installerPath);
            var fullRoot = Path.GetFullPath(updateRoot) + Path.DirectorySeparatorChar;
            if (!fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show("Путь обновления находится вне защищённого каталога загрузок.", "DefenderGuard — обновление", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return 1;
            }

            if (!AppUpdater.VerifyDownloadedPackage(fullPath, expectedSha256, out var verification))
            {
                MessageBox.Show(verification, "DefenderGuard — обновление", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return 1;
            }

            var protection = SelfProtectionManager.GetStatus();
            var restoreProtection = protection.Installed;
            if (restoreProtection)
            {
                var disabled = SelfProtectionManager.Disable();
                if (!disabled.Success || SelfProtectionManager.GetStatus().Running)
                {
                    MessageBox.Show("Не удалось временно отключить самозащиту перед обновлением.", "DefenderGuard — обновление", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return 1;
                }
            }

            var start = new ProcessStartInfo(installerPath)
            {
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(installerPath) ?? AppContext.BaseDirectory
            };
            start.ArgumentList.Add("/quiet");
            start.ArgumentList.Add("/norestart");
            var isElevated = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            if (!isElevated)
                start.Verb = "runas";

            using var installer = Process.Start(start) ?? throw new InvalidOperationException("Не удалось запустить проверенный установщик.");

            var appPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "DefenderGuard",
                "DefenderGuard.exe");
            var escapedInstallerId = installer.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
            var escapedInstallerPath = fullPath.Replace("'", "''", StringComparison.Ordinal);
            var pendingStorePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "DemoGuard",
                "update-pending.json");
            var escapedPendingStorePath = pendingStorePath.Replace("'", "''", StringComparison.Ordinal);
            var escapedAppPath = appPath.Replace("'", "''", StringComparison.Ordinal);
            var restoreCode = restoreProtection
                ? $"$restore = Start-Process -FilePath '{escapedAppPath}' -ArgumentList @('--self-protection-diagnostic','install') -Verb RunAs -Wait -PassThru; if ($restore.ExitCode -ne 0) {{ Start-Process -FilePath 'explorer.exe' -ArgumentList @('{escapedAppPath}') -WindowStyle Hidden; }}"
                : string.Empty;
            var relaunchCode = $"if (Test-Path -LiteralPath '{escapedAppPath}') {{ Start-Process -FilePath 'explorer.exe' -ArgumentList @('{escapedAppPath}') -WindowStyle Hidden; }}";
            var cleanupCode = $"Remove-Item -LiteralPath '{escapedInstallerPath}' -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath '{escapedPendingStorePath}' -Force -ErrorAction SilentlyContinue";
            var finalizer = "$p = Get-Process -Id " + escapedInstallerId + " -ErrorAction SilentlyContinue; " +
                            "if ($p) { $p.WaitForExit() }; " +
                            "$exit = if ($p) { $p.ExitCode } else { 0 }; " +
                            "if ($exit -eq 0) { " + restoreCode + " " + relaunchCode + " " + cleanupCode + " } " +
                            "else { " + restoreCode + " " + relaunchCode + " }";

            var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(finalizer));
            Process.Start(new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                Arguments = $"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"
            });

            return 0;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return 2;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "DefenderGuard — обновление", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
