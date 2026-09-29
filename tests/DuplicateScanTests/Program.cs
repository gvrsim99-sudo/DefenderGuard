using DemoGuard;

var result = DuplicateFileService.ScanDefaultUserFolders(
    (percent, message) => Console.WriteLine($"{percent}%|{message}"));

Console.WriteLine($"RESULT|files={result.FilesScanned}|candidates={result.CandidateFiles}|groups={result.Groups.Count}|reclaimable={DuplicateFileService.FormatBytes(result.ReclaimableBytes)}");
foreach (var group in result.Groups.Take(20))
{
    Console.WriteLine($"GROUP|size={DuplicateFileService.FormatBytes(group.FileSizeBytes)}|count={group.Files.Count}|reclaimable={DuplicateFileService.FormatBytes(group.ReclaimableBytes)}|sha256={group.Sha256}");
    foreach (var file in group.Files)
        Console.WriteLine($"FILE|{file.Path}");
}