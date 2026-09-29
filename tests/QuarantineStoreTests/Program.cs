using System.Security.Cryptography;
using System.Text.Json;
using DemoGuard;

static void Assert(bool condition, string message)
{
    if (!condition) throw new Exception("FAIL: " + message);
}

var root = Path.Combine(Path.GetTempPath(), "DefenderGuard-QTest-" + Guid.NewGuid().ToString("N"));
var q = Path.Combine(root, "Quarantine");
Directory.CreateDirectory(root);
try
{
    var source = Path.Combine(root, "sample.txt");
    var original = "benign test content";
    File.WriteAllText(source, original);
    var item = QuarantineStore.Add(source, q);
    Assert(!File.Exists(source), "source should be moved out after verified copy");
    Assert(File.Exists(item.StoredPath), "quarantine copy exists");
    Assert(QuarantineStore.VerifyStoredFile(item, q, out _), "stored SHA-256 verifies");

    File.WriteAllText(source, "new file that must not be overwritten");
    var restored = QuarantineStore.Restore(item, q);
    Assert(restored.RestoredPath != source, "restore should choose alternate name on conflict");
    Assert(File.ReadAllText(source) == "new file that must not be overwritten", "existing destination preserved");
    Assert(File.ReadAllText(restored.RestoredPath) == original, "original bytes restored");
    Assert(restored.RemovedFromQuarantine, "quarantine copy removed after restore");

    if (OperatingSystem.IsWindows())
    {
        var target = Path.Combine(root, "reparse-target.txt");
        var link = Path.Combine(root, "reparse-link.txt");
        File.WriteAllText(target, "outside quarantine");
        try
        {
            File.CreateSymbolicLink(link, target);
            var rejected = false;
            try { QuarantineStore.Add(link, q); } catch (IOException) { rejected = true; } catch (UnauthorizedAccessException) { rejected = true; }
            Assert(rejected, "a reparse-point source must be rejected instead of following its target");
            Assert(File.Exists(target) && File.ReadAllText(target) == "outside quarantine", "reparse rejection must not touch the target");
        }
        catch (UnauthorizedAccessException) { Console.WriteLine("SKIP: symbolic-link regression test requires the Windows symbolic-link privilege."); }
    }

    var tamperSource = Path.Combine(root, "tamper.bin");
    File.WriteAllBytes(tamperSource, [1, 2, 3, 4, 5]);
    var tamperItem = QuarantineStore.Add(tamperSource, q);
    File.SetAttributes(tamperItem.StoredPath, FileAttributes.Normal);
    File.WriteAllBytes(tamperItem.StoredPath, [9, 9, 9]);
    Assert(!QuarantineStore.VerifyStoredFile(tamperItem, q, out _), "tampered copy is rejected");
    var threw = false;
    try { QuarantineStore.Restore(tamperItem, q); } catch (IOException) { threw = true; }
    Assert(threw, "tampered file restore throws");
    Assert(!File.Exists(tamperSource), "tampered restore does not recreate original");

    var deleteSource = Path.Combine(root, "delete-me.bin");
    File.WriteAllText(deleteSource, "test data for permanent quarantine removal");
    var deleteItem = QuarantineStore.Add(deleteSource, q);
    var deleteMetadata = Path.Combine(q, deleteItem.Id + ".json");
    QuarantineStore.Delete(deleteItem, q);
    Assert(!File.Exists(deleteItem.StoredPath), "full delete removes the quarantined payload");
    Assert(!File.Exists(deleteMetadata), "full delete removes quarantine metadata");
    Assert(QuarantineStore.Load(q).All(loadedItem => loadedItem.Id != deleteItem.Id), "deleted quarantine item is absent after reload");

    var changedAfterScan = Path.Combine(root, "changed-after-scan.bin");
    File.WriteAllText(changedAfterScan, "content as seen during analysis");
    var expectedScanHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(changedAfterScan)));
    File.WriteAllText(changedAfterScan, "different content written after analysis");
    var staleHashRejected = false;
    try { QuarantineStore.Add(changedAfterScan, q, expectedScanHash); }
    catch (IOException ex) { staleHashRejected = ex.Message.Contains("изменился после анализа", StringComparison.OrdinalIgnoreCase); }
    Assert(staleHashRejected, "a file changed since analysis must be rejected by expected SHA-256");
    Assert(File.ReadAllText(changedAfterScan) == "different content written after analysis", "hash mismatch must preserve the original file");
    Assert(!Directory.EnumerateFiles(q, "*.stage").Any(), "hash mismatch must clean the staged quarantine copy");

    var legacyId = Guid.NewGuid().ToString("N");
    var legacyStored = Path.Combine(q, legacyId + ".qtn");
    var legacyMetadata = Path.Combine(q, legacyId + ".json");
    Directory.CreateDirectory(q);
    File.WriteAllText(legacyStored, "old EICAR prototype data");
    File.WriteAllText(legacyMetadata, JsonSerializer.Serialize(new { Id = legacyId, OriginalPath = Path.Combine(root, "legacy.dat"), StoredPath = legacyStored, DetectedAt = DateTime.Now, OriginalName = "legacy.dat" }));
    var loaded = QuarantineStore.Load(q).Single(x => x.Id == legacyId);
    Assert(loaded.Length == new FileInfo(legacyStored).Length && !string.IsNullOrWhiteSpace(loaded.Sha256), "legacy record migrates hash and length");
    Assert(loaded.QuarantinedAt != default, "legacy timestamp migrates");

    Console.WriteLine("PASS: verified copy, conflict-safe restore, complete quarantine deletion, tamper rejection, stale analysis hash rejection, legacy migration.");
}
finally
{
    try { Directory.Delete(root, recursive: true); } catch { }
}