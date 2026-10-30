using System.Net;
using System.Reflection.PortableExecutable;
using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing.Etlx;

namespace Coaptic.WindowsStack;

// No FindSymbolFilePath, LookupSymbolsForModule, source lookup, symbol path environment,
// module opening from ETL paths, or symbol-server access is used. The ONLY PDB opened is
// the supplied file; DIA's direct loadDataFromPdb is the v3.1.21 implementation.
internal sealed class OwnedSymbols : IDisposable
{
    private readonly FileStream exe;
    private readonly FileStream pdb;
    private readonly PEReader pe;
    private readonly SymbolReader reader;
    private readonly NativeSymbolModule module;
    public ImageIdentity Identity { get; }
    private readonly CaptureConfig config;

    public OwnedSymbols(CaptureConfig config)
    {
        this.config = config;
        Wire.LocalPath(config.Exe); Wire.LocalPath(config.Pdb);
        // Read sharing denies writes and deletion throughout identity validation and use.
        exe = new FileStream(config.Exe, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            pdb = new FileStream(config.Pdb, FileMode.Open, FileAccess.Read, FileShare.Read);
            try
            {
                var exeHash = Wire.Hash(exe); var pdbHash = Wire.Hash(pdb);
                Wire.EqualHash(config.ExeSha256, exeHash); Wire.EqualHash(config.PdbSha256, pdbHash);
                pe = new PEReader(exe, PEStreamOptions.LeaveOpen);
                try
                {
                    var cv = pe.ReadDebugDirectory().Where(e => e.Type == DebugDirectoryEntryType.CodeView).ToArray();
                    if (cv.Length != 1) throw new InvalidDataException("Exactly one native EXE CodeView record required.");
                    var signature = pe.ReadCodeViewDebugDirectoryData(cv[0]);
                    if (signature.Guid == Guid.Empty || signature.Age <= 0)
                        throw new InvalidDataException("Unknown PDB GUID/age is not a match.");
                    reader = new SymbolReader(TextWriter.Null, "", new DenyNetwork()) { SourcePath = "" };
                    try
                    {
                        module = reader.OpenNativeSymbolFile(config.Pdb) ??
                            throw new InvalidDataException("Owned file is not a native Windows PDB.");
                        RequireMatch(signature.Guid, signature.Age, module.PdbGuid, module.PdbAge);
                        var header = pe.PEHeaders.PEHeader ?? throw new InvalidDataException("PE header missing.");
                        Identity = new(exeHash, pdbHash, signature.Guid, signature.Age,
                            pe.PEHeaders.CoffHeader.TimeDateStamp, header.SizeOfImage, header.CheckSum);
                    }
                    catch { reader.Dispose(); throw; }
                }
                catch { pe.Dispose(); throw; }
            }
            catch { pdb.Dispose(); throw; }
        }
        catch { exe.Dispose(); throw; }
    }

    internal static void RequireMatch(Guid exeGuid, int exeAge, Guid pdbGuid, int pdbAge)
    {
        if (exeGuid == Guid.Empty || exeAge <= 0 || exeGuid != pdbGuid || exeAge != pdbAge)
            throw new InvalidDataException("Exact local EXE/PDB GUID+age mismatch.");
    }

    public Frame Resolve(TraceCodeAddress address, ModuleBinding binding, int sampleProcessIndex, long sampleQpc)
    {
        var file = address.ModuleFile;
        var label = file is null ? "[unknown-module]" : file.FilePath;
        Wire.Text(label);
        var raw = address.Address.ToString("x");
        var name = "";
        // Code addresses and module-file indices can be shared across processes.
        // Only the validated sample's process and selected mapping authorize lookup.
        if (file is not null && binding.TryRva(sampleProcessIndex, sampleQpc,
            (int)file.ModuleFileIndex, address.Address, out var rva))
            name = module.FindNameForRva(rva);
        // Keep all other modules, including kernel addresses, visible and unresolved.
        var unresolved = string.IsNullOrEmpty(name);
        var symbol = unresolved ? label + "!0x" + raw + " [unresolved]" : Path.GetFileName(config.Exe) + "!" + name;
        Wire.Text(symbol);
        return new(symbol, raw, label, unresolved);
    }

    public void VerifyUnchanged()
    {
        Wire.EqualHash(Identity.ExeSha256, Wire.Hash(exe));
        Wire.EqualHash(Identity.PdbSha256, Wire.Hash(pdb));
    }
    public void Dispose() { reader.Dispose(); pe.Dispose(); pdb.Dispose(); exe.Dispose(); }

    private sealed class DenyNetwork : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new WebException("Network access is forbidden for owned local symbols.");
    }
}

internal sealed record NativeMapping(int ProcessIndex, int ModuleIndex, string Path, ulong Base, long Size,
    double LoadMSec, double UnloadMSec);

// Created only after mapping selection and a complete, contradiction-free raw scan.
// The selected mapping covers the entire half-open QPC window; samples must also
// satisfy its raw transition bounds (where present) or its finite ETLX bounds.
internal sealed record ModuleBinding(NativeMapping Mapping, long StartQpc, long StopQpc,
    double StartMSec, long Frequency, long? LoadQpc, long? UnloadQpc)
{
    public bool TryRva(int processIndex, long qpc, int moduleIndex, ulong address, out uint rva)
    {
        rva = 0;
        if (processIndex != Mapping.ProcessIndex || moduleIndex != Mapping.ModuleIndex ||
            qpc < StartQpc || qpc >= StopQpc || Frequency <= 0 || address < Mapping.Base ||
            !ModuleAttribution.ValidRange(Mapping.Base, Mapping.Size)) return false;
        var relative = StartMSec + (qpc - StartQpc) * (1000.0 / Frequency);
        if (!double.IsFinite(relative) ||
            (LoadQpc.HasValue ? qpc < LoadQpc.Value : relative < Mapping.LoadMSec) ||
            (UnloadQpc.HasValue ? qpc >= UnloadQpc.Value : relative >= Mapping.UnloadMSec)) return false;
        var offset = address - Mapping.Base;
        if (offset >= (ulong)Mapping.Size || offset > uint.MaxValue) return false;
        rva = checked((uint)offset);
        return true;
    }
}

// Production-shared pure model. Only scalar scan state is retained: a later zero
// or matching record can never erase an earlier contradiction. Diagnostic row
// capacity is deliberately unrelated to validation capacity.
internal sealed class ModuleAttribution
{
    private readonly ImageIdentity image;
    private readonly int pid, processIndex;
    private readonly string expectedName;
    private readonly ulong capturedBase;
    private readonly long start, stop, frequency;
    private readonly double startMSec, stopMSec;
    private readonly bool liveOwnedBinding;
    private NativeMapping? selected;
    private long? loadQpc, unloadQpc;
    private bool mappingSelected, aggregateChecked, scanComplete, kernelObserved;
    public string? Contradiction { get; private set; }
    public int CandidateCount { get; private set; }
    public int EventsInspected { get; private set; }
    public bool ScanComplete => scanComplete;
    public double WindowStartMSec => startMSec;
    public double WindowStopMSec => stopMSec;
    public bool RecordedZeroImageId { get; private set; }
    public bool NonzeroImageIdMatched { get; private set; }
    public bool RawDebugIdMatched { get; private set; }
    public bool RawEmptyDebugId { get; private set; }
    public bool RawHeaderAbsent { get; private set; }
    public int AggregateImageId { get; private set; }
    public string AggregateDebugIdStatus { get; private set; } = "unchecked";
    public string AggregateImageIdStatus => !aggregateChecked ? "unchecked" :
        AggregateImageId == 0 && !RecordedZeroImageId ? "unavailable-aggregate-zero" :
        ImageIdStatus(AggregateImageId, image.ImageId, liveOwnedBinding);
    public string RawDebugIdStatus => RawDebugIdMatched ? "matched" :
        RawEmptyDebugId ? "unavailable-recorded-empty" : scanComplete ? "absent" : "scan-incomplete";

    public ModuleAttribution(ImageIdentity image, int pid, int processIndex, string expectedName,
        ulong capturedBase, long start, long stop, long frequency, double startMSec, double stopMSec,
        bool liveOwnedBinding)
    {
        this.image = image; this.pid = pid; this.processIndex = processIndex; this.expectedName = expectedName;
        this.capturedBase = capturedBase; this.start = start; this.stop = stop; this.frequency = frequency;
        this.startMSec = startMSec; this.stopMSec = stopMSec; this.liveOwnedBinding = liveOwnedBinding;
        if (!liveOwnedBinding || pid <= 0 || processIndex < 0 || start <= 0 || stop <= start || frequency <= 0 ||
            !ValidRange(capturedBase, image.ImageSize) || image.PdbGuid == Guid.Empty || image.PdbAge <= 0 ||
            !Covers(startMSec, stopMSec, startMSec, stopMSec))
            throw new InvalidDataException("Independent live owned-file identity/window binding required.");
    }

    internal static bool ValidRange(ulong address, long size) =>
        address != 0 && size > 0 && (ulong)size <= ulong.MaxValue - address;
    internal static bool Covers(double load, double unload, double start, double stop) =>
        double.IsFinite(load) && double.IsFinite(unload) && double.IsFinite(start) && double.IsFinite(stop) &&
        start < stop && load <= start && unload >= stop;
    internal static void RequireUniqueLifetime(int count)
    {
        if (count != 1) throw new InvalidDataException("Missing/ambiguous numeric PID/TID lifetime, including reuse.");
    }
    public bool Relevant(ulong address, long size, string path) =>
        address == capturedBase || string.Equals(Path.GetFileName(path), expectedName, StringComparison.OrdinalIgnoreCase) ||
        // Subtraction also detects overlapping candidates whose end would overflow.
        (address >= capturedBase ? address - capturedBase < (ulong)image.ImageSize :
            size > 0 && capturedBase - address < (ulong)size);

    public NativeMapping SelectMapping(IEnumerable<NativeMapping> mappings)
    {
        if (selected is not null) throw new InvalidDataException("Mapping already selected.");
        foreach (var mapping in mappings)
        {
            if (!Relevant(mapping.Base, mapping.Size, mapping.Path)) continue;
            CandidateCount++;
            if (CandidateCount > 1) throw new InvalidDataException("Duplicate/overlapping/conflicting target mappings.");
            selected = mapping;
        }
        var m = selected;
        if (m is null || m.ProcessIndex != processIndex || m.ModuleIndex < 0 ||
            m.Base != capturedBase || m.Size != image.ImageSize ||
            !string.Equals(Path.GetFileName(m.Path), expectedName, StringComparison.OrdinalIgnoreCase) ||
            !Covers(m.LoadMSec, m.UnloadMSec, startMSec, stopMSec))
            throw new InvalidDataException("Exactly one native owned mapping covering the entire window required.");
        mappingSelected = true;
        return m;
    }

    internal static string ImageIdStatus(int observed, int expected, bool liveBinding) => observed == 0
        ? liveBinding ? "unavailable-recorded-zero" : "refused-no-live-binding"
        : observed == expected ? "matched" : "contradiction";
    internal static string DebugIdStatus(Guid observed, int age, ImageIdentity expected) => observed == Guid.Empty
        ? age == 0 ? "unavailable-recorded-empty" : "contradiction"
        : observed == expected.PdbGuid && age == expected.PdbAge ? "matched" : "contradiction";
    private void Refuse(string reason) => Contradiction ??= reason;
    private void ImageId(int value, bool raw)
    {
        if (ImageIdStatus(value, image.ImageId, liveOwnedBinding) is "contradiction" or "refused-no-live-binding")
            Refuse("Contradictory image timestamp.");
        if (raw && value == 0) RecordedZeroImageId = true;
        if (raw && value != 0 && value == image.ImageId) NonzeroImageIdMatched = true;
    }
    public void ObserveAggregate(int imageId, uint checksum, Guid guid, int age)
    {
        if (!mappingSelected || aggregateChecked) throw new InvalidDataException("Select mapping before metadata.");
        aggregateChecked = true; AggregateImageId = imageId;
        ImageId(imageId, false);
        if (checksum != image.ImageChecksum) Refuse("Contradictory aggregate checksum, including zero.");
        AggregateDebugIdStatus = DebugIdStatus(guid, age, image);
        if (AggregateDebugIdStatus == "contradiction") Refuse("Contradictory aggregate DebugID.");
    }
    public void CountEvent()
    {
        if (EventsInspected >= 1_000_000)
        {
            Refuse("Raw event bound exceeded; scan incomplete.");
            throw new InvalidDataException(Contradiction);
        }
        EventsInspected++;
    }
    public bool ObserveKernel(int eventPid, long qpc, int opcode, ulong address, long size, string path,
        bool headerPresent, int timestamp, uint checksum)
    {
        if (eventPid != pid || !Relevant(address, size, path)) return false;
        kernelObserved = true;
        if (qpc <= 0 || address != capturedBase || size != image.ImageSize ||
            !string.Equals(Path.GetFileName(path), expectedName, StringComparison.OrdinalIgnoreCase))
            Refuse("Contradictory raw native mapping.");
        if (headerPresent)
        {
            ImageId(timestamp, true);
            if (checksum != image.ImageChecksum) Refuse("Contradictory raw checksum, including zero.");
        }
        else RawHeaderAbsent = true;
        // Kernel Image/Load is opcode 10, Unload is 2. DCStart(3)/DCEnd(4)
        // describe observations, not transitions, and never narrow lifetime bounds.
        if (opcode == 10)
        {
            if (qpc >= start && qpc < stop) Refuse("Image load inside selected window.");
            if (qpc < start) loadQpc = !loadQpc.HasValue ? qpc : Math.Max(loadQpc.Value, qpc);
        }
        else if (opcode == 2)
        {
            if (qpc < stop) Refuse("Image unload before the selected window ends.");
            unloadQpc = !unloadQpc.HasValue ? qpc : Math.Min(unloadQpc.Value, qpc);
        }
        else if (opcode is not (3 or 4)) Refuse("Unknown relevant image opcode.");
        return true;
    }
    private bool RelevantSymbol(int eventPid, ulong address, long size, string path)
    {
        if (eventPid > 0 && eventPid != pid) return false;
        if (!Relevant(address, size, path)) return false;
        // Do not infer a process from a shared base or ETLX's timestamp-only
        // synthetic association. Ambiguous synthetic provenance refuses safely.
        if (eventPid != pid) Refuse("Relevant synthetic metadata lacks target PID attribution.");
        if (address != capturedBase) Refuse("Conflicting synthetic image base.");
        return true;
    }
    public bool ObserveImageId(int eventPid, ulong address, long size, string path, int timestamp)
    {
        if (!RelevantSymbol(eventPid, address, size, path)) return false;
        if (size != image.ImageSize) Refuse("Conflicting synthetic image size.");
        ImageId(timestamp, true);
        return true;
    }
    public bool ObserveDebugId(int eventPid, ulong address, Guid guid, int age)
    {
        if (!RelevantSymbol(eventPid, address, 0, "")) return false;
        var status = DebugIdStatus(guid, age, image);
        if (status == "contradiction") Refuse("Contradictory raw DebugID.");
        RawDebugIdMatched |= status == "matched";
        RawEmptyDebugId |= status == "unavailable-recorded-empty";
        return true;
    }
    public void CompleteScan(bool completed)
    {
        scanComplete = completed;
        if (!completed) Refuse("Raw stream did not complete.");
    }
    public ModuleBinding Finish(bool conversionTruncated)
    {
        if (Contradiction is not null) throw new InvalidDataException(Contradiction);
        if (!mappingSelected || selected is null || CandidateCount != 1 || !aggregateChecked || !scanComplete ||
            EventsInspected == 0 || !kernelObserved || conversionTruncated)
            throw new InvalidDataException("Incomplete mapping/metadata/raw-stream validation.");
        return new(selected, start, stop, startMSec, frequency, loadQpc, unloadQpc);
    }
}
