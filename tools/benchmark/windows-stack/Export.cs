using System.Globalization;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace Coaptic.WindowsStack;

internal static class Export
{
    public static int Run(ExportConfig config)
    {
        config.Validate(); OwnedSession.ValidatePin();
        var capture = Wire.Read<CaptureReceipt>(config.CaptureReceipt);
        ValidateReceipt(capture);
        Wire.LocalPath(capture.Etl);
        // Keep the ETL immutable as well as the explicitly owned image/PDB. Conversion
        // uses a fresh explicit path; OpenOrConvert could silently reuse stale ETLX.
        using var etl = new FileStream(capture.Etl, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (etl.Length != capture.EtlBytes || etl.Length > config.MaxEtlBytes)
            throw new InvalidDataException("Owned ETL size mismatch/budget exceeded.");
        Wire.EqualHash(capture.EtlSha256, Wire.Hash(etl));
        using var symbols = new OwnedSymbols(capture.Config);
        if (symbols.Identity != capture.Image) throw new InvalidDataException("Capture image identity differs from owned EXE/PDB.");
        var capturedBase = ulong.Parse(capture.ModuleBaseAddress, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
        if (capturedBase == 0 || capture.ModuleSize != symbols.Identity.ImageSize)
            throw new InvalidDataException("Invalid live owned-image binding.");
        var etlx = Path.Combine(config.ScratchDirectory, "capture.etlx");
        var conversionLoss = 0; var conversionTruncated = false;
        var options = new TraceLogOptions
        {
            ConversionLog = TextWriter.Null,
            ContinueOnError = false,
            // Explicitly prohibit conversion-time symbol discovery (which could open
            // foreign EXEs/PDBs or use the environment's symbol-server configuration).
            ShouldResolveSymbols = _ => false,
            LocalSymbolsOnly = true,
            MaxEventCount = 1_000_000,
            OnLostEvents = (truncated, lost, _) =>
            {
                conversionTruncated |= truncated;
                conversionLoss = Math.Max(conversionLoss, lost);
            }
        };
        // FileOnly prevents TraceEvent's default MergeAll discovery from adding
        // unbound sibling .kernel/.clr/.user ETLs to the hashed input.
        using (var input = new ETWTraceEventSource(capture.Etl, TraceEventSourceType.FileOnly))
            TraceLog.CreateFromEventTraceLogFile(input, etlx, options);
        if (Directory.EnumerateFiles(config.ScratchDirectory, "*", SearchOption.AllDirectories)
            .Sum(p => new FileInfo(p).Length) > config.MaxConversionBytes)
            throw new InvalidDataException("Conversion byte budget exceeded; retained for parent cleanup.");
        // The parent watchdog supplies the during-conversion disk/RSS/time bounds.
        // This postcheck is deliberately not represented as a hard conversion cap.
        using var log = new TraceLog(etlx);
        var processes = log.Processes.Where(p => p.ProcessID == capture.Config.Pid).Take(2).ToArray();
        if (processes.Length != 1) throw new InvalidDataException("Missing/ambiguous trace PID lifetime (including reuse).");
        var process = processes[0];
        if (process.StartTime.ToUniversalTime() > capture.ReadyUtc.UtcDateTime ||
            process.EndTime.ToUniversalTime() < capture.ReadyUtc.UtcDateTime)
            throw new InvalidDataException("Trace PID lifetime does not cover ready.");
        var targetModules = process.LoadedModules.Where(m => m.ModuleFile is not null &&
            symbols.Matches(m.ModuleFile, capturedBase)).Take(2).ToArray();
        if (targetModules.Length != 1)
        {
            // Diagnose the retained input before changing any identity policy. A
            // failed diagnostic must not replace the original matching refusal.
            try { WriteModuleDiagnostic(config, capture, symbols, process, capturedBase, targetModules.Length); }
            catch (Exception error)
            {
                Console.Error.WriteLine("Module diagnostic unavailable: " + DiagnosticText(error.Message));
            }
            throw new InvalidDataException("ETL target module does not match captured live owned EXE mapping and header/PDB identity.");
        }
        var targetFile = targetModules[0].ModuleFile;
        var accumulator = new Samples(capture.Config.Pid, capture.Config.Tid, capture.StartQpc, capture.StopQpc,
            capture.QpcFrequency);
        var wrongLifetime = 0;
        long nativeCountSum = 0;
        foreach (var sample in log.Events.ByEventType<SampledProfileTraceData>())
        {
            var qpc = RawQpc(sample);
            if (!accumulator.InScope(sample.ProcessID, sample.ThreadID, qpc)) continue;
            if (sample.Process().ProcessIndex != process.ProcessIndex) { wrongLifetime++; continue; }
            nativeCountSum += sample.Count;
            var frames = new List<Frame>(128);
            var stack = sample.CallStack();
            while (stack is not null && frames.Count < 128)
            {
                frames.Add(symbols.Resolve(stack.CodeAddress, capturedBase));
                stack = stack.Caller;
            }
            var truncated = stack is not null;
            if (truncated)
            {
                frames.RemoveAt(127);
                frames.Add(new("[truncated-root-ancestry]", "0", "[unknown-module]", true));
            }
            if (frames.Count == 0)
                frames.Add(new("[missing-stack]!0x" + sample.InstructionPointer.ToString("x"),
                    sample.InstructionPointer.ToString("x"), "[unknown-module]", true));
            accumulator.Add(sample.ThreadID, qpc, process.Name, frames, truncated);
        }
        if (wrongLifetime != 0) throw new InvalidDataException("Selected samples reference a different PID lifetime.");
        if (log.EventsLost < 0 || conversionLoss < 0) throw new InvalidDataException("Invalid loss count.");
        var loss = Math.Max(capture.Lost, Math.Max(log.EventsLost, conversionLoss));
        var notes = Capture.Notes + " Weights count observed SampledProfile events, not CPU milliseconds or the event payload Count. " +
            "Only supplied EXE/PDB symbols; all other modules/kernel remain unresolved. " +
            "Symbol provenance: live owned-image receipt path/base/size/header + exact EXE/PDB SHA256/GUID/age; " +
            (targetFile.PdbSignature == Guid.Empty ? "ETL has no target DebugID, none claimed. " : "ETL target DebugID also matched. ") +
            $"Conversion truncated={conversionTruncated}; depth-truncated samples={accumulator.Truncated}; " +
            $"ETW log buffers lost={capture.LogBuffersLost}; realtime buffers lost={capture.RealTimeBuffersLost}. " +
            "Inlining and native unwind completeness unknown; missing/partial ancestry retained. " +
            "Conversion workspace/RSS bounded by parent watchdog, not this postcheck.";
        var profile = accumulator.Finish(capture.Config.Identity, capture.Config.Label, loss, notes);
        if (process.Threads.Where(t => t.ThreadID == profile.Scope.Tid).Take(2).Count() != 1)
            throw new InvalidDataException("Selected numeric TID has missing/ambiguous lifetime, including reuse.");
        symbols.VerifyUnchanged(); Wire.EqualHash(capture.EtlSha256, Wire.Hash(etl));
        Wire.WriteNew(config.Output, profile);
        var receiptPath = config.Output + ".receipt.json";
        Wire.WriteNew(receiptPath, new
        {
            schema = "coaptic-windows-stack-export/1", tool = Wire.Tool,
            capture_receipt_sha256 = Wire.HashFile(config.CaptureReceipt), capture.Config.CaptureId,
            etl_sha256 = capture.EtlSha256, image = symbols.Identity,
            module_base_address = capture.ModuleBaseAddress, capture.ModuleSize,
            symbol_provenance = "live-owned-image", embedded_debug_id_matched = targetFile.PdbSignature != Guid.Empty,
            output_sha256 = Wire.HashFile(config.Output), output_bytes = new FileInfo(config.Output).Length,
            conversion_truncated = conversionTruncated, depth_truncated_samples = accumulator.Truncated,
            total_samples = profile.Totals.Samples, unresolved_frame_occurrences = accumulator.Unresolved,
            native_sampled_profile_payload_count_sum = nativeCountSum,
            lost = loss, capture.LogBuffersLost, capture.RealTimeBuffersLost,
            qualification = "unqualified sampled-event attribution only; no CPU-share or hardware claim"
        }, 65536);
        Wire.Emit("exported", capture.Config.CaptureId, new { output = config.Output, receipt = receiptPath });
        return 0;
    }

    private static string DiagnosticText(string value) => value.Length <= 96 ? value : value[..96];

    private static void WriteModuleDiagnostic(ExportConfig config, CaptureReceipt capture, OwnedSymbols symbols,
        TraceProcess process, ulong capturedBase, int matchingCountCappedAtTwo)
    {
        var image = symbols.Identity;
        var expectedName = Path.GetFileName(capture.Config.Exe);
        var candidates = process.LoadedModules.Where(m => m.ModuleFile is not null &&
            (m.ImageBase == capturedBase || string.Equals(Path.GetFileName(m.ModuleFile.FilePath),
                expectedName, StringComparison.OrdinalIgnoreCase))).Take(17).ToArray();
        var rows = candidates.Take(16).Select(m =>
        {
            var file = m.ModuleFile;
            return new
            {
                module_file_index = (int)file.ModuleFileIndex, process_index = (int)m.Process.ProcessIndex,
                path = DiagnosticText(file.FilePath), path_clipped = file.FilePath.Length > 96,
                loaded_base = m.ImageBase.ToString("x"), file_base = file.ImageBase.ToString("x"),
                size = file.ImageSize, image_id = unchecked((uint)file.ImageId).ToString("x8"),
                checksum = unchecked((uint)file.ImageChecksum).ToString("x8"), file.PdbSignature, file.PdbAge,
                load_relative_ms = FiniteDiagnosticTime(m.LoadTimeRelativeMSec),
                unload_relative_ms = FiniteDiagnosticTime(m.UnloadTimeRelativeMSec),
                predicates = new
                {
                    basename = string.Equals(Path.GetFileName(file.FilePath), expectedName, StringComparison.OrdinalIgnoreCase),
                    live_base = file.ImageBase == capturedBase, size = file.ImageSize == image.ImageSize,
                    debug_id = file.PdbSignature == Guid.Empty ? file.PdbAge == 0 :
                        file.PdbSignature == image.PdbGuid && file.PdbAge == image.PdbAge,
                    image_id = file.ImageId == image.ImageId,
                    checksum = unchecked((uint)file.ImageChecksum) == image.ImageChecksum,
                    complete_match = symbols.Matches(file, capturedBase)
                },
                notes = "Aggregate zero fields do not distinguish absent metadata from a recorded zero."
            };
        }).ToArray();
        var raw = new List<object>(32);
        var rawOverflow = false;
        var eventCount = 0;
        // ETLX can collapse or replace image metadata. Read raw ETL events without
        // opening any module path; retain earlier contradictory observations too.
        using (var source = new ETWTraceEventSource(capture.Etl, TraceEventSourceType.FileOnly))
        {
            source.AllEvents += _ =>
            {
                if (++eventCount > 1_000_000) throw new InvalidDataException("Raw diagnostic event bound exceeded.");
            };
            source.Kernel.ImageGroup += data =>
            {
                if (data.ProcessID != capture.Config.Pid || (data.ImageBase != capturedBase &&
                    !string.Equals(Path.GetFileName(data.FileName), expectedName, StringComparison.OrdinalIgnoreCase))) return;
                if (raw.Count == 32) { rawOverflow = true; return; }
                raw.Add(new
                {
                    data.ProcessID, data.Version, opcode = (int)data.Opcode, qpc = RawQpc(data),
                    path = DiagnosticText(data.FileName), path_clipped = data.FileName.Length > 96,
                    live_base = data.ImageBase.ToString("x"), size = data.ImageSize,
                    timestamp = unchecked((uint)data.TimeDateStamp).ToString("x8"),
                    checksum = unchecked((uint)data.ImageChecksum).ToString("x8"),
                    default_base = data.DefaultBase.ToString("x"), header_fields_present = data.Version >= 2
                });
            };
            source.Process();
        }
        Wire.WriteNew(config.Output + ".module-diagnostic.json", new
        {
            schema = "coaptic-windows-module-diagnostic/1", capture.Config.CaptureId,
            input_etl_sha256 = capture.EtlSha256, process_index = (int)process.ProcessIndex,
            capture.Config.Pid, capture.Config.Tid, matching_count_capped_at_two = matchingCountCappedAtTwo,
            expected = new { path = DiagnosticText(capture.Config.Exe), live_base = capturedBase.ToString("x"),
                image.ImageSize, image_id = unchecked((uint)image.ImageId).ToString("x8"),
                checksum = image.ImageChecksum.ToString("x8"), image.PdbGuid, image.PdbAge },
            candidates = rows, candidates_overflow = candidates.Length > 16,
            raw_image_events = raw, raw_image_events_overflow = rawOverflow, raw_events_inspected = eventCount,
            notes = "Diagnostic only; identity refusal unchanged. Paths are ETL text, never opened. No field is synthesized or treated as matched."
        }, 65536);
    }

    private static double? FiniteDiagnosticTime(double value) => double.IsFinite(value) ? value : null;

    private static long RawQpc(Microsoft.Diagnostics.Tracing.TraceEvent sample)
    {
        // The capture receipt uses Stopwatch's native QPC counter. Keep that exact
        // integer domain: TraceEvent 3.1.21 marks this accessor obsolete in favor of
        // relative/DateTime APIs, which do not preserve the receipt's exact values.
#pragma warning disable CS0618
        return sample.TimeStampQPC;
#pragma warning restore CS0618
    }

    internal static void ValidateReceipt(CaptureReceipt capture)
    {
        var c = capture.Config;
        c.Identity.Validate(); Wire.Text(c.Label); Wire.LocalPath(c.Directory);
        if (capture.Schema != "coaptic-windows-stack-capture/1" || !capture.Stopped ||
            c.CaptureId == Guid.Empty || c.Pid <= 0 || c.Tid is <= 0 || capture.StartQpc <= 0 ||
            capture.StopQpc <= capture.StartQpc || capture.QpcFrequency <= 0 || capture.Lost < 0 ||
            capture.ReadyUtc < c.ProcessStartUtc || capture.StoppedUtc < capture.ReadyUtc ||
            capture.SessionName != c.SessionName || capture.Etl != c.Etl ||
            capture.EtlBytes is <= 0 or > 134217728 ||
            capture.StopQpc - capture.StartQpc > capture.QpcFrequency * 120L)
            throw new InvalidDataException("Invalid/incomplete owned capture receipt.");
        Wire.Digest(capture.EtlSha256);
    }
}

// Pure bounded model: one PID/lifetime window and exactly one selected/observed TID.
// Every row is one sample, so aligned addresses/modules are retained without pooling.
internal sealed class Samples(int pid, int? tid, long start, long stop, long frequency)
{
    private readonly List<StackRow> rows = new();
    private readonly int? selectedTid = tid;
    private int? observedTid = tid;
    private int frameCount;
    private long textBytes;
    public long Unresolved { get; private set; }
    public int Truncated { get; private set; }
    public bool InScope(int samplePid, int sampleTid, long qpc) =>
        samplePid == pid && (!selectedTid.HasValue || sampleTid == selectedTid.Value) && qpc >= start && qpc < stop;
    public void Add(int sampleTid, long qpc, string comm, List<Frame> leafToRoot, bool truncated)
    {
        if (sampleTid <= 0 || qpc < start || qpc >= stop || frequency <= 0 || leafToRoot.Count is < 1 or > 128)
            throw new InvalidDataException("Invalid sample/thread/window/depth.");
        if (observedTid.HasValue && sampleTid != observedTid.Value)
            throw new InvalidDataException("Mixed thread scope refused; select exactly one TID.");
        observedTid = sampleTid;
        if (rows.Count >= 100_000 || frameCount + leafToRoot.Count > 200_000)
            throw new InvalidDataException("Stack/frame count budget exceeded.");
        Wire.Text(comm);
        foreach (var frame in leafToRoot)
        {
            Wire.Text(frame.Symbol); Wire.Text(frame.Module);
            textBytes += System.Text.Encoding.UTF8.GetByteCount(frame.Symbol) +
                System.Text.Encoding.UTF8.GetByteCount(frame.Address) + System.Text.Encoding.UTF8.GetByteCount(frame.Module);
            if (textBytes > Wire.ExportLimit) throw new InvalidDataException("Frame text budget exceeded.");
            if (frame.Unresolved) Unresolved++;
        }
        frameCount += leafToRoot.Count;
        if (truncated) Truncated++;
        var rootToLeaf = leafToRoot.AsEnumerable().Reverse().ToArray();
        rows.Add(new(rootToLeaf.Select(f => f.Symbol).ToArray(), 1, 1,
            new(comm, Wire.Stamp(qpc, frequency), 1, "SampledProfile",
                rootToLeaf.Select(f => f.Address).ToArray(), rootToLeaf.Select(f => f.Module).ToArray())));
    }
    public Profile Finish(Identity identity, string label, long loss, string notes)
    {
        if (rows.Count == 0) throw new InvalidDataException("No selected PID/TID/window samples; no profile emitted.");
        identity.Validate(); Wire.Text(label); Wire.Text(notes);
        if (loss < 0) throw new InvalidDataException("Negative loss count.");
        return new("coaptic-stack-profile/1", identity, new("sampled_cpu", "samples"),
            new(loss, Unresolved, 0, notes), new(pid, observedTid, label, "unknown"),
            new(rows.Count, rows.Count), rows);
    }
}
