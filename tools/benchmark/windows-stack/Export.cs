using System.Globalization;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
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
        ModuleAttribution.RequireUniqueLifetime(processes.Length);
        var process = processes[0];
        // v3.1.21 exposes module QPC bounds only internally. Anchor its public
        // relative bounds to an event's raw QPC; never use module DateTime getters
        // (that version incorrectly treats QPC as FILETIME).
        var anchor = log.Events.FirstOrDefault() ?? throw new InvalidDataException("Empty converted trace.");
        var (startMSec, stopMSec) = RelativeWindow(RawQpc(anchor), anchor.TimeStampRelativeMSec, capture);
        if (!ModuleAttribution.Covers(process.StartTimeRelativeMsec, process.EndTimeRelativeMsec, startMSec, stopMSec))
            throw new InvalidDataException("Trace PID lifetime does not cover the entire selected window.");
        var attribution = new ModuleAttribution(symbols.Identity, capture.Config.Pid, (int)process.ProcessIndex,
            Path.GetFileName(capture.Config.Exe), capturedBase, capture.StartQpc, capture.StopQpc,
            capture.QpcFrequency, startMSec, stopMSec, liveOwnedBinding: true);
        var raw = new List<object>(32);
        var rawOverflow = false;
        void Retain(object row)
        {
            if (raw.Count < 32) raw.Add(row);
            else rawOverflow = true;
        }
        ModuleBinding binding;
        var rawScanStarted = false;
        try
        {
            var selectedMapping = attribution.SelectMapping(process.LoadedModules.Where(m => m is not TraceManagedModule && m.ModuleFile is not null)
                .Select(m => new NativeMapping((int)m.Process.ProcessIndex, (int)m.ModuleFile.ModuleFileIndex,
                    m.ModuleFile.FilePath, m.ImageBase, m.ModuleFile.ImageSize,
                    m.LoadTimeRelativeMSec, m.UnloadTimeRelativeMSec)));
            // Selection counted every relevant mapping before inspecting metadata.
            var targetFile = process.LoadedModules.Single(m => m is not TraceManagedModule && m.ModuleFile is not null &&
                (int)m.ModuleFile.ModuleFileIndex == selectedMapping.ModuleIndex).ModuleFile;
            attribution.ObserveAggregate(targetFile.ImageId, unchecked((uint)targetFile.ImageChecksum),
                targetFile.PdbSignature, targetFile.PdbAge);
            rawScanStarted = true;
            ReadRaw(capture, attribution, Retain);
            binding = attribution.Finish(conversionTruncated);
        }
        catch (Exception)
        {
            // Preserve the original refusal even if bounded diagnostic output fails.
            if (!rawScanStarted)
            {
                try { ReadRaw(capture, attribution, Retain); }
                catch (Exception error)
                {
                    Console.Error.WriteLine("Raw module diagnostic incomplete: " + DiagnosticText(error.Message));
                }
            }
            try { WriteModuleDiagnostic(config, capture, symbols, process, capturedBase, attribution, raw, rawOverflow); }
            catch (Exception error)
            {
                Console.Error.WriteLine("Module diagnostic unavailable: " + DiagnosticText(error.Message));
            }
            throw;
        }
        var accumulator = new Samples(capture.Config.Pid, capture.Config.Tid, capture.StartQpc, capture.StopQpc,
            capture.QpcFrequency, config.AggregateExactPaths);
        var wrongLifetime = 0;
        long nativeCountSum = 0;
        foreach (var sample in log.Events.ByEventType<SampledProfileTraceData>())
        {
            var qpc = RawQpc(sample);
            if (!accumulator.InScope(sample.ProcessID, sample.ThreadID, qpc)) continue;
            var sampleProcess = sample.Process();
            if (sampleProcess is null || sampleProcess.ProcessIndex != process.ProcessIndex) { wrongLifetime++; continue; }
            nativeCountSum = checked(nativeCountSum + sample.Count);
            var frames = new List<Frame>(128);
            var stack = sample.CallStack();
            while (stack is not null && frames.Count < 128)
            {
                frames.Add(symbols.Resolve(stack.CodeAddress, binding, (int)sampleProcess.ProcessIndex, qpc));
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
            "Symbol provenance: independent live owned-file receipt path/base/size + locked EXE/PDB SHA256/GUID/age; " +
            "not proof of exact in-memory bytes or protection against hostile pre-lock replacement. " +
            $"ETLX ImageId observed={unchecked((uint)attribution.AggregateImageId):x8}, expected={unchecked((uint)symbols.Identity.ImageId):x8}, " +
            $"state={attribution.AggregateImageIdStatus}; raw recorded zero={attribution.RecordedZeroImageId}, raw nonzero matched={attribution.NonzeroImageIdMatched}. " +
            $"ETLX DebugID={attribution.AggregateDebugIdStatus}; raw DebugID={attribution.RawDebugIdStatus}; absent/empty is not matched. " +
            $"Complete FileOnly raw validation inspected {attribution.EventsInspected} events; zero timestamp cause unknown. " +
            $"Conversion truncated={conversionTruncated}; depth-truncated samples={accumulator.Truncated}; " +
            $"ETW log buffers lost={capture.LogBuffersLost}; realtime buffers lost={capture.RealTimeBuffersLost}. " +
            "Inlining and native unwind completeness unknown; missing/partial ancestry retained. " +
            "Conversion workspace/RSS bounded by parent watchdog, not this postcheck.";
        var profile = accumulator.Finish(capture.Config.Identity, capture.Config.Label, loss, notes);
        ModuleAttribution.RequireUniqueLifetime(process.Threads.Where(t => t.ThreadID == profile.Scope.Tid).Take(2).Count());
        symbols.VerifyUnchanged(); Wire.EqualHash(capture.EtlSha256, Wire.Hash(etl));
        Wire.WriteNew(config.Output, profile);
        var receiptPath = config.Output + ".receipt.json";
        var receipt = new
        {
            schema = "coaptic-windows-stack-export/1", tool = Wire.Tool,
            capture_receipt_sha256 = Wire.HashFile(config.CaptureReceipt), capture.Config.CaptureId,
            etl_sha256 = capture.EtlSha256, image = symbols.Identity,
            module_base_address = capture.ModuleBaseAddress, capture.ModuleSize,
            symbol_provenance = "live-owned-file-binding", exact_in_memory_bytes_proven = false,
            embedded_debug_id_matched = attribution.AggregateDebugIdStatus == "matched",
            module_file_index = binding.Mapping.ModuleIndex, process_index = binding.Mapping.ProcessIndex,
            window_start_qpc = binding.StartQpc, window_stop_qpc = binding.StopQpc,
            mapping_load_relative_ms = binding.Mapping.LoadMSec, mapping_unload_relative_ms = binding.Mapping.UnloadMSec,
            mapping_load_qpc = binding.LoadQpc, mapping_unload_qpc = binding.UnloadQpc,
            image_id_observed = unchecked((uint)attribution.AggregateImageId).ToString("x8"),
            image_id_expected = unchecked((uint)symbols.Identity.ImageId).ToString("x8"),
            image_id_state = attribution.AggregateImageIdStatus,
            raw_recorded_zero_image_id = attribution.RecordedZeroImageId,
            raw_nonzero_image_id_matched = attribution.NonzeroImageIdMatched,
            raw_header_absent = attribution.RawHeaderAbsent,
            aggregate_debug_id_state = attribution.AggregateDebugIdStatus, raw_debug_id_state = attribution.RawDebugIdStatus,
            raw_scan_complete = true, raw_events_inspected = attribution.EventsInspected,
            output_sha256 = Wire.HashFile(config.Output), output_bytes = new FileInfo(config.Output).Length,
            conversion_truncated = conversionTruncated, depth_truncated_samples = accumulator.Truncated,
            total_samples = profile.Totals.Samples, unresolved_frame_occurrences = accumulator.Unresolved,
            native_sampled_profile_payload_count_sum = nativeCountSum,
            lost = loss, capture.LogBuffersLost, capture.RealTimeBuffersLost,
            qualification = "unqualified sampled-event attribution only; no CPU-share or hardware claim"
        };
        if (config.AggregateExactPaths)
        {
            // Preserve the existing receipt verbatim in default mode. Projection
            // provenance extends it without changing the original capture identity.
            var projectedReceipt = System.Text.Json.JsonSerializer.SerializeToNode(receipt, Wire.Json)!.AsObject();
            projectedReceipt["projection"] = System.Text.Json.JsonSerializer.SerializeToNode(new
            {
                aggregate_exact_paths = true, kind = "exact-full-symbol-paths",
                notes = Samples.ProjectionNotes,
                identity = profile.Identity, pid = profile.Scope.Pid, tid = profile.Scope.Tid,
                capture.QpcFrequency,
                raw_samples = accumulator.RawSamples, output_distinct_rows = profile.Stacks.Count,
                raw_frame_occurrences = accumulator.RawFrameOccurrences,
                weighted_output_frame_occurrences = accumulator.WeightedOutputFrameOccurrences,
                app_ancestry_samples = accumulator.AppAncestrySamples,
                unresolved_frame_occurrences = accumulator.Unresolved, depth_truncated_samples = accumulator.Truncated,
                total_samples = profile.Totals.Samples, total_weight = profile.Totals.Weight,
                totals_conserved = true
            }, Wire.Json);
            Wire.WriteNew(receiptPath, projectedReceipt, 65536);
        }
        else Wire.WriteNew(receiptPath, receipt, 65536);
        Wire.Emit("exported", capture.Config.CaptureId, new { output = config.Output, receipt = receiptPath });
        return 0;
    }

    private static string DiagnosticText(string value) => value.Length <= 96 ? value : value[..96];

    private static (double Start, double Stop) RelativeWindow(long anchorQpc, double anchorMSec, CaptureReceipt capture)
    {
        if (anchorQpc <= 0 || !double.IsFinite(anchorMSec)) throw new InvalidDataException("Invalid ETLX clock anchor.");
        var scale = 1000.0 / capture.QpcFrequency;
        var start = anchorMSec + (capture.StartQpc - anchorQpc) * scale;
        var stop = anchorMSec + (capture.StopQpc - anchorQpc) * scale;
        if (!ModuleAttribution.Covers(start, stop, start, stop)) throw new InvalidDataException("Invalid ETLX window bounds.");
        return (start, stop);
    }

    private static void ReadRaw(CaptureReceipt capture, ModuleAttribution attribution, Action<object> retain)
    {
        // Mandatory validation of the one hash-locked input. Never discover sibling
        // ETLs, open recorded paths, merge, or let diagnostic capacity stop checking.
        using var source = new ETWTraceEventSource(capture.Etl, TraceEventSourceType.FileOnly);
        source.AllEvents += _ => attribution.CountEvent();
        source.Kernel.ImageGroup += data =>
        {
            if (!attribution.ObserveKernel(data.ProcessID, RawQpc(data), (int)data.Opcode,
                data.ImageBase, data.ImageSize, data.FileName, data.Version >= 2,
                data.TimeDateStamp, unchecked((uint)data.ImageChecksum))) return;
            retain(new
            {
                kind = "kernel-image", data.ProcessID, data.Version, opcode = (int)data.Opcode, qpc = RawQpc(data),
                path = DiagnosticText(data.FileName), path_clipped = data.FileName.Length > 96,
                live_base = data.ImageBase.ToString("x"), size = data.ImageSize,
                timestamp = unchecked((uint)data.TimeDateStamp).ToString("x8"),
                checksum = unchecked((uint)data.ImageChecksum).ToString("x8"),
                default_base = data.DefaultBase.ToString("x"), header_fields_present = data.Version >= 2
            });
        };
        // Exact pinned v3.1.21 parser and body fields, independent of ETLX's
        // last-record aggregation. Synthetic events are optional, never fabricated.
        var symbols = new SymbolTraceEventParser(source);
        symbols.ImageID += data =>
        {
            if (!attribution.ObserveImageId(data.ProcessID, data.ImageBase, data.ImageSize,
                data.OriginalFileName, data.TimeDateStamp)) return;
            retain(new { kind = "image-id", data.ProcessID, qpc = RawQpc(data), live_base = data.ImageBase.ToString("x"),
                size = data.ImageSize, timestamp = unchecked((uint)data.TimeDateStamp).ToString("x8"),
                path = DiagnosticText(data.OriginalFileName), path_clipped = data.OriginalFileName.Length > 96 });
        };
        symbols.ImageIDDbgID_RSDS += data =>
        {
            if (!attribution.ObserveDebugId(data.ProcessID, data.ImageBase, data.GuidSig, data.Age)) return;
            retain(new { kind = "debug-id-rsds", data.ProcessID, qpc = RawQpc(data),
                live_base = data.ImageBase.ToString("x"), data.GuidSig, data.Age,
                path = DiagnosticText(data.PdbFileName), path_clipped = data.PdbFileName.Length > 96 });
        };
        attribution.CompleteScan(source.Process());
    }

    private static void WriteModuleDiagnostic(ExportConfig config, CaptureReceipt capture, OwnedSymbols symbols,
        TraceProcess process, ulong capturedBase, ModuleAttribution attribution, List<object> raw, bool rawOverflow)
    {
        var image = symbols.Identity;
        var expectedName = Path.GetFileName(capture.Config.Exe);
        var candidates = process.LoadedModules.Where(m => m.ModuleFile is not null &&
            attribution.Relevant(m.ImageBase, m.ModuleFile.ImageSize, m.ModuleFile.FilePath)).Take(17).ToArray();
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
                    debug_id_state = ModuleAttribution.DebugIdStatus(file.PdbSignature, file.PdbAge, image),
                    image_id_state = file.ImageId == 0 ? "unavailable-aggregate-zero" :
                        ModuleAttribution.ImageIdStatus(file.ImageId, image.ImageId, true),
                    checksum = unchecked((uint)file.ImageChecksum) == image.ImageChecksum,
                    entire_window = ModuleAttribution.Covers(m.LoadTimeRelativeMSec, m.UnloadTimeRelativeMSec,
                        attribution.WindowStartMSec, attribution.WindowStopMSec)
                },
                notes = "Aggregate zero fields do not distinguish absent metadata from a recorded zero."
            };
        }).ToArray();
        Wire.WriteNew(config.Output + ".module-diagnostic.json", new
        {
            schema = "coaptic-windows-module-diagnostic/1", capture.Config.CaptureId,
            input_etl_sha256 = capture.EtlSha256, process_index = (int)process.ProcessIndex,
            capture.Config.Pid, capture.Config.Tid, relevant_count_capped_at_two = attribution.CandidateCount,
            expected = new { path = DiagnosticText(capture.Config.Exe), live_base = capturedBase.ToString("x"),
                image.ImageSize, image_id = unchecked((uint)image.ImageId).ToString("x8"),
                checksum = image.ImageChecksum.ToString("x8"), image.PdbGuid, image.PdbAge },
            candidates = rows, candidates_overflow = candidates.Length > 16,
            raw_image_events = raw, raw_image_events_overflow = rawOverflow, raw_events_inspected = attribution.EventsInspected,
            raw_scan_complete = attribution.ScanComplete, contradiction = attribution.Contradiction,
            image_id_state = attribution.AggregateImageIdStatus,
            notes = "Diagnostic only; refusal retained. Paths are ETL text, never opened. Row caps do not cap validation. " +
                "Recorded zero is unavailable corroboration, not a match; cause unknown. Independent live owned-file binding is not exact in-memory proof."
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
            capture.QpcFrequency > long.MaxValue / 120L ||
            capture.StopQpc - capture.StartQpc > capture.QpcFrequency * 120L)
            throw new InvalidDataException("Invalid/incomplete owned capture receipt.");
        Wire.Digest(capture.EtlSha256);
    }
}

// Pure bounded model: one PID/lifetime window and exactly one selected/observed TID.
// Default rows retain aligned event metadata. Explicit projection retains only
// distinct full symbol paths; raw limits and quality counts still precede grouping.
internal sealed class Samples(int pid, int? tid, long start, long stop, long frequency,
    bool aggregateExactPaths = false)
{
    public const string ProjectionNotes = "Explicit exact-full-symbol-path flame projection: canonical JSON omits " +
        "per-event timestamps, addresses, modules, comm and event order; it is not a trace timeline. " +
        "The retained original hash-bound ETL is authoritative for event metadata and independent replay; " +
        "aggregate JSON alone does not validate event timestamps.";
    private readonly List<StackRow> rows = new();
    private readonly bool aggregatePaths = aggregateExactPaths;
    private readonly SortedDictionary<string[], int>? pathRows = aggregateExactPaths
        ? new(new PathComparer()) : null;
    private readonly int? selectedTid = tid;
    private int? observedTid = tid;
    private int frameCount;
    private long textBytes;
    public int RawSamples { get; private set; }
    public long RawFrameOccurrences => frameCount;
    public long WeightedOutputFrameOccurrences { get; private set; }
    public long AppAncestrySamples { get; private set; }
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
        if (RawSamples >= 100_000 || checked(frameCount + leafToRoot.Count) > 200_000)
            throw new InvalidDataException("Stack/frame count budget exceeded.");
        Wire.Text(comm);
        long sampleTextBytes = 0;
        var unresolved = 0;
        var appAncestry = false;
        foreach (var frame in leafToRoot)
        {
            Wire.Text(frame.Symbol); Wire.Text(frame.Module); Wire.Text(frame.Address);
            // Projection cannot rely on Python's per-event metadata validation:
            // even a duplicate path must validate every discarded address/module.
            if (!frame.Address.All(char.IsAsciiHexDigit)) throw new InvalidDataException("Invalid frame address.");
            sampleTextBytes = checked(sampleTextBytes + System.Text.Encoding.UTF8.GetByteCount(frame.Symbol));
            if (!aggregatePaths)
                sampleTextBytes = checked(sampleTextBytes + System.Text.Encoding.UTF8.GetByteCount(frame.Address) +
                    System.Text.Encoding.UTF8.GetByteCount(frame.Module));
            if (frame.Unresolved) unresolved = checked(unresolved + 1);
            appAncestry |= frame.Symbol.Contains("coaptic::app::", StringComparison.Ordinal);
        }
        var symbols = new string[leafToRoot.Count];
        for (var i = 0; i < symbols.Length; i++) symbols[i] = leafToRoot[^(i + 1)].Symbol;
        if (pathRows is not null && pathRows.TryGetValue(symbols, out var index))
        {
            var row = rows[index];
            rows[index] = row with { Samples = checked(row.Samples + 1), Weight = checked(row.Weight + 1) };
        }
        else
        {
            var retainedBytes = checked(textBytes + sampleTextBytes);
            if (retainedBytes > Wire.ExportLimit) throw new InvalidDataException("Frame text budget exceeded.");
            SampleEvent? sampleEvent = null;
            if (!aggregatePaths)
            {
                var rootToLeaf = leafToRoot.AsEnumerable().Reverse().ToArray();
                sampleEvent = new(comm, Wire.Stamp(qpc, frequency), 1, "SampledProfile",
                    rootToLeaf.Select(f => f.Address).ToArray(), rootToLeaf.Select(f => f.Module).ToArray());
            }
            // The tree provides collision-independent structural lookup. The list
            // preserves deterministic first-seen ETL order without retaining events.
            pathRows?.Add(symbols, rows.Count);
            rows.Add(new(symbols, 1, 1, sampleEvent));
            textBytes = retainedBytes;
        }
        observedTid = sampleTid;
        RawSamples = checked(RawSamples + 1);
        frameCount = checked(frameCount + leafToRoot.Count);
        Unresolved = checked(Unresolved + unresolved);
        if (truncated) Truncated = checked(Truncated + 1);
        if (appAncestry) AppAncestrySamples = checked(AppAncestrySamples + 1);
    }
    public Profile Finish(Identity identity, string label, long loss, string notes)
    {
        if (RawSamples == 0) throw new InvalidDataException("No selected PID/TID/window samples; no profile emitted.");
        if (aggregatePaths) notes += " " + ProjectionNotes;
        identity.Validate(); Wire.Text(label); Wire.Text(notes);
        if (loss < 0) throw new InvalidDataException("Negative loss count.");
        long outputSamples = 0, outputWeight = 0, weightedFrames = 0, outputAppSamples = 0;
        foreach (var row in rows)
        {
            outputSamples = checked(outputSamples + row.Samples);
            outputWeight = checked(outputWeight + row.Weight);
            weightedFrames = checked(weightedFrames + checked((long)row.Weight * row.Frames.Length));
            if (row.Frames.Any(f => f.Contains("coaptic::app::", StringComparison.Ordinal)))
                outputAppSamples = checked(outputAppSamples + row.Samples);
        }
        if (outputSamples != RawSamples || outputWeight != RawSamples || weightedFrames != frameCount ||
            outputAppSamples != AppAncestrySamples)
            throw new InvalidDataException("Projected sample/frame/App totals do not conserve raw input.");
        WeightedOutputFrameOccurrences = weightedFrames;
        return new("coaptic-stack-profile/1", identity, new("sampled_cpu", "samples"),
            new(loss, Unresolved, 0, notes), new(pid, observedTid, label, "unknown"),
            new(RawSamples, RawSamples), rows);
    }

    private sealed class PathComparer : IComparer<string[]>
    {
        public int Compare(string[]? x, string[]? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;
            var length = x.Length.CompareTo(y.Length);
            if (length != 0) return length;
            for (var i = 0; i < x.Length; i++)
            {
                var symbol = StringComparer.Ordinal.Compare(x[i], y[i]);
                if (symbol != 0) return symbol;
            }
            return 0;
        }
    }
}
