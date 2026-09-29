using System.Diagnostics;

const string exe = @"C:\Users\User\Downloads\DefenderGuard.exe";

AssertExit("status", 2);
AssertExit("install", 0);
AssertExit("status", 0);
AssertExit("disable", 0);
AssertExit("status", 2);
Console.WriteLine("PASS: self-protection install/start/status/disable on the published EXE.");

int AssertExit(string operation, int expected)
{
    using var process = Process.Start(new ProcessStartInfo
    {
        FileName = exe,
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        ArgumentList = { "--self-protection-diagnostic", operation }
    }) ?? throw new InvalidOperationException("Не удалось запустить DefenderGuard.exe.");

    if (!process.WaitForExit(180000))
    {
        try { process.Kill(entireProcessTree: true); } catch { }
        throw new InvalidOperationException("Тайм-аут диагностики: " + operation);
    }

    var output = process.StandardOutput.ReadToEnd().Trim();
    var error = process.StandardError.ReadToEnd().Trim();
    Console.WriteLine($"RUN|{operation}|exit={process.ExitCode}");
    Console.WriteLine(output);
    if (!string.IsNullOrWhiteSpace(error)) Console.WriteLine(error);

    if (process.ExitCode != expected)
        throw new InvalidOperationException($"Неожиданный код для {operation}: {process.ExitCode}, ожидался {expected}.");

    return process.ExitCode;
}