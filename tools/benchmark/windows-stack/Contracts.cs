using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Coaptic.WindowsStack;

// Wire names are deliberately shared with the parent's Python orchestrator.
internal sealed record Identity(string Source, string Tool, string Workload, string Capture,
    string Platform, string Cohort)
{
    public void Validate()
    {
        foreach (var s in new[] { Source, Tool, Workload, Capture, Platform, Cohort }) Wire.Text(s);
    }
}

internal sealed record CaptureConfig(Guid CaptureId, string Directory, int Pid, int? Tid,
    DateTimeOffset ProcessStartUtc, string Exe, string ExeSha256, string Pdb, string PdbSha256,
    Identity Identity, string Label, int MaxSeconds, bool DedicatedHostedVm)
{
    [JsonIgnore] public string SessionName => "CoapticStack-" + CaptureId.ToString("D");
    [JsonIgnore] public string Etl => Path.Combine(Directory, "capture.etl");
    public void Validate()
    {
        if (CaptureId == Guid.Empty || Pid <= 0 || Tid is <= 0 || MaxSeconds is < 1 or > 120 ||
            ProcessStartUtc == default || ProcessStartUtc.Offset != TimeSpan.Zero)
            throw new InvalidDataException("Invalid capture identity, scope, lifetime or deadline.");
        Wire.LocalPath(Directory); Wire.LocalPath(Exe); Wire.LocalPath(Pdb);
        if (!System.IO.Directory.Exists(Directory)) throw new InvalidDataException("Output directory must exist.");
        Identity.Validate(); Wire.Text(Label); Wire.Digest(ExeSha256); Wire.Digest(PdbSha256);
        foreach (var name in new[] { "capture.etl", "capture.json", "failure.json", "started.json" })
            Wire.Fresh(Path.Combine(Directory, name));
    }
}

internal sealed record ExportConfig(string CaptureReceipt, string Output, string ScratchDirectory,
    long MaxEtlBytes, long MaxConversionBytes)
{
    public void Validate()
    {
        Wire.LocalPath(CaptureReceipt); Wire.LocalPath(Output); Wire.LocalPath(ScratchDirectory);
        Wire.Fresh(Output); Wire.Fresh(Output + ".receipt.json");
        if (MaxEtlBytes is < 1 or > 134217728 || MaxConversionBytes is < 1 or > 268435456)
            throw new InvalidDataException("Invalid ETL/conversion budget.");
        if (!Directory.Exists(ScratchDirectory) || Directory.EnumerateFileSystemEntries(ScratchDirectory).Any())
            throw new InvalidDataException("Conversion scratch must be an existing empty owned directory.");
    }
}

internal sealed record ImageIdentity(string ExeSha256, string PdbSha256, Guid PdbGuid, int PdbAge,
    int ImageId, int ImageSize, uint ImageChecksum);
internal sealed record CaptureReceipt(string Schema, CaptureConfig Config, ImageIdentity Image,
    string SessionName, string Etl, string EtlSha256, long EtlBytes, long StartQpc, long StopQpc,
    long QpcFrequency, DateTimeOffset ReadyUtc, DateTimeOffset StoppedUtc, long Lost,
    uint LogBuffersLost, uint RealTimeBuffersLost, bool Stopped, string Notes,
    string ModuleBaseAddress, int ModuleSize);
internal sealed record Frame(string Symbol, string Address, string Module, bool Unresolved);
internal sealed record SampleEvent(string Comm, string Timestamp, int Period, string Name,
    string[] Addresses, string[] Dsos);
internal sealed record StackRow(string[] Frames, int Weight, int Samples, SampleEvent Event);
internal sealed record Measurement(string Kind, string Unit);
internal sealed record Quality(long? Lost, long? Unresolved, long? Refused, string Notes);
internal sealed record Scope(int Pid, int? Tid, string Label, string CpuMode);
internal sealed record Totals(long Samples, long Weight);
internal sealed record Profile(string Schema, Identity Identity, Measurement Measurement,
    Quality Quality, Scope Scope, Totals Totals, IReadOnlyList<StackRow> Stacks);

internal static class Wire
{
    public const string Tool = "Coaptic.WindowsStack/1;TraceEvent/3.1.21;net8.0;x64";
    public const int ExportLimit = 16 * 1024 * 1024;
    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false,
        MaxDepth = 32
    };
    public static T Read<T>(string path, int limit = 65536)
    {
        LocalPath(path);
        using var file = File.OpenRead(path);
        if (file.Length > limit) throw new InvalidDataException("JSON input budget exceeded.");
        return JsonSerializer.Deserialize<T>(file, Json) ?? throw new InvalidDataException("Null JSON input.");
    }
    public static void Text(string s)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Length > 4096 || s.Any(char.IsControl) ||
            s.Any(char.IsSurrogate)) throw new InvalidDataException("Invalid bounded text.");
    }
    public static void Digest(string s)
    {
        if (s is null || s.Length != 64 || !s.All(char.IsAsciiHexDigit))
            throw new InvalidDataException("SHA256 required.");
    }
    public static string Hash(Stream stream)
    {
        stream.Position = 0;
        var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        stream.Position = 0;
        return hash;
    }
    public static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Hash(stream);
    }
    public static void EqualHash(string expected, string actual)
    {
        Digest(expected);
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Owned input SHA256 mismatch.");
    }
    public static void LocalPath(string path)
    {
        var normalized = NormalizeLocalPath(path);
        // Refuse existing reparse components rather than following links into unrelated resources.
        for (string? p = normalized; !string.IsNullOrEmpty(p); p = Path.GetDirectoryName(p))
            if ((File.Exists(p) || Directory.Exists(p)) &&
                (File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Reparse paths are not owned local inputs.");
    }
    internal static string NormalizeLocalPath(string path)
    {
        Text(path);
        // Inspect the RAW prefix before normalization or filesystem queries. Both
        // slash forms of UNC and every extended/device prefix fail this drive rule.
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' ||
            path[2] is not ('\\' or '/') || path.IndexOf(':', 2) >= 0 ||
            path.IndexOfAny(new[] { '?', '*', '"', '<', '>', '|' }) >= 0)
            throw new InvalidDataException("Ordinary absolute drive path required; no UNC/device/ADS paths.");
        var ordinary = path.Replace('/', '\\');
        foreach (var part in ordinary[3..].Split('\\'))
        {
            if (part is "" or "." or "..") continue;
            if (part.EndsWith(' ') || part.EndsWith('.'))
                throw new InvalidDataException("Ambiguous Windows path component.");
            var stem = part.Split('.')[0].ToUpperInvariant();
            if (stem is "CON" or "PRN" or "AUX" or "NUL" or "CLOCK$" ||
                stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) ||
                    stem.StartsWith("LPT", StringComparison.Ordinal)) &&
                    (char.IsAsciiDigit(stem[3]) || stem[3] is '\u00b9' or '\u00b2' or '\u00b3'))
                throw new InvalidDataException("Windows device name is not an owned file.");
        }
        return Path.GetFullPath(ordinary);
    }
    public static void Fresh(string path)
    {
        LocalPath(path);
        if (File.Exists(path) || Directory.Exists(path)) throw new IOException("Output already exists: " + path);
    }
    public static void WriteNew<T>(string path, T value, int limit = ExportLimit)
    {
        // Stream to a fresh file with a hard byte refusal; a partial file is retained as failure evidence.
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        using var bounded = new LimitedStream(file, limit);
        JsonSerializer.Serialize(bounded, value, Json);
        bounded.Flush(); file.Flush(true);
    }
    public static void Emit(string status, Guid captureId, object? detail = null)
    {
        Console.Out.WriteLine(JsonSerializer.Serialize(new { status, capture_id = captureId, detail }, Json));
        Console.Out.Flush();
    }
    public static string Stamp(long qpc, long frequency) =>
        ((decimal)qpc / frequency).ToString("0.000000000", CultureInfo.InvariantCulture);
}

internal sealed class LimitedStream(Stream inner, long maximum) : Stream
{
    private long written;
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length > maximum - written) throw new InvalidDataException("Output byte budget exceeded.");
        inner.Write(buffer); written += buffer.Length;
    }
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => written;
    public override long Position { get => written; set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
