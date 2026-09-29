using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DemoGuard;

internal static class SafeFileAccess
{
    public static FileStream OpenRegularFileRead(string path, int bufferSize = 128 * 1024)
    {
        if (!OperatingSystem.IsWindows())
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, bufferSize, FileOptions.SequentialScan);

        var handle = CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Не удалось открыть файл Windows.");
        }
        try
        {
            if (!GetFileInformationByHandleEx(handle, FILE_INFO_BY_HANDLE_CLASS.FileAttributeTagInfo,
                out var info, (uint)Marshal.SizeOf<FILE_ATTRIBUTE_TAG_INFO>()))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось получить атрибуты открытого файла Windows.");

            if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                throw new IOException("Reparse-point файл запрещён в защищённой операции чтения.");

            return new FileStream(handle, FileAccess.Read, bufferSize, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

    private enum FILE_INFO_BY_HANDLE_CLASS { FileAttributeTagInfo = 9 }
    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_ATTRIBUTE_TAG_INFO
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile, FILE_INFO_BY_HANDLE_CLASS fileInformationClass,
        out FILE_ATTRIBUTE_TAG_INFO fileInformation, uint bufferSize);
}