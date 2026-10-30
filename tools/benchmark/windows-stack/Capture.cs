using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace Coaptic.WindowsStack;

internal static class Capture
{
    public const string Notes = "Dedicated ephemeral hosted administrator VM only. EnableKernelProvider(Profile) writes the MACHINE-GLOBAL 1ms sample interval. " +
        "Handle-only stop does not restore a prior global interval. Configured circular ETL 64MiB and requested buffers 64MiB are NOT a whole-resource cap; " +
        "TraceEvent permits additional buffers. Parent must bound ETL, conversion, RSS, output and runtime. " +
        "Window includes control transit after ready and before stop; sampled counts are not qualified CPU shares. Circular overwrite is not fully measurable.";

    public static void HostedPreflight(CaptureConfig config)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess || !config.DedicatedHostedVm ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows")
            throw new InvalidOperationException("Capture refused: dedicated ephemeral GitHub-hosted Windows x64 VM attestation required; local elevation is insufficient.");
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Capture refused: hosted administrator token required.");
        OwnedSession.ValidatePin();
    }

    public static Process ValidateTarget(CaptureConfig config)
    {
        var process = Process.GetProcessById(config.Pid);
        try
        {
            // Pin the process HANDLE for the entire capture. Numeric PID lookup alone
            // could otherwise observe a replacement process after PID reuse.
            _ = process.SafeHandle;
            RecheckTarget(process, config);
            return process;
        }
        catch { process.Dispose(); throw; }
    }

    public static void RecheckTarget(Process process, CaptureConfig config)
    {
        process.Refresh();
        if (process.HasExited || process.StartTime.ToUniversalTime().Ticks != config.ProcessStartUtc.UtcDateTime.Ticks ||
            !string.Equals(Path.GetFullPath(process.MainModule?.FileName ?? ""), Path.GetFullPath(config.Exe), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Target PID/lifetime/EXE mismatch or exit.");
        if (config.Tid.HasValue)
        {
            var found = false;
            foreach (ProcessThread thread in process.Threads)
            {
                using (thread) if (thread.Id == config.Tid.Value) found = true;
            }
            if (!found) throw new InvalidDataException("Selected TID does not belong to target lifetime.");
        }
    }

    public static async Task<int> Run(CaptureConfig config)
    {
        config.Validate(); HostedPreflight(config);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(config.MaxSeconds));
        ConsoleCancelEventHandler onCancel = (_, e) => { e.Cancel = true; deadline.Cancel(); };
        Console.CancelKeyPress += onCancel;
        TraceEventSession? session = null;
        OwnedSession? owned = null;
        var cleanupSettled = true;
        var stopAttempted = false;
        OwnedSession.StopResult? finalStats = null;
        var input = new CommandInput(Console.In);
        long start = 0, stop = 0;
        try
        {
            using var symbols = new OwnedSymbols(config);
            using var process = ValidateTarget(config);
            session = new TraceEventSession(config.SessionName, config.Etl,
                TraceEventSessionOptions.Create | TraceEventSessionOptions.NoRestartOnCreate);
            session.StopOnDispose = false; // BEFORE enable, even before adapter validation.
            session.BufferSizeMB = 64;
            session.CircularBufferMB = 64;
            session.CpuSampleIntervalMSec = 1.0f;
            session.StackCompression = false;
            owned = new OwnedSession(session);
            Wire.Emit("armed", config.CaptureId, new { session_name = config.SessionName, etl = config.Etl });
            await input.Expect("start", deadline.Token);
            RecheckTarget(process, config);
            // From this point a thrown enable can still mean a successfully started owned
            // OS session. The catch path always inspects the pinned successful handle.
            cleanupSettled = false;
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread |
                KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.Profile,
                KernelTraceEventParser.Keywords.Profile);
            if (!owned.ObserveStart().HasValue) throw new InvalidOperationException("Enable returned without an owned native session.");
            Wire.WriteNew(Path.Combine(config.Directory, "started.json"), new
            {
                schema = "coaptic-windows-stack-start/1", config.CaptureId, session_name = config.SessionName,
                etl = config.Etl, successful_start_handle = owned.Handle!.Value.ToString("x"), tool = Wire.Tool
            }, 65536);
            deadline.Token.ThrowIfCancellationRequested();
            RecheckTarget(process, config);
            var moduleBase = process.MainModule!.BaseAddress;
            var moduleSize = process.MainModule.ModuleMemorySize;
            if (moduleSize != symbols.Identity.ImageSize) throw new InvalidDataException("Live target module size differs from owned EXE.");
            var readyUtc = DateTimeOffset.UtcNow;
            start = Stopwatch.GetTimestamp();
            Wire.Emit("ready", config.CaptureId, new { start_qpc = start, qpc_frequency = Stopwatch.Frequency });
            await input.Expect("stop", deadline.Token);
            stop = Stopwatch.GetTimestamp(); // bound samples BEFORE flushing/stopping ETW.
            // Stop BEFORE target validation, hashing, receipt output, or any failure-prone
            // postprocessing. Even a worker that exited unexpectedly must settle ETW first.
            stopAttempted = true;
            var stats = owned.Stop();
            finalStats = stats;
            cleanupSettled = true;
            RecheckTarget(process, config);
            if (process.MainModule!.BaseAddress != moduleBase || process.MainModule.ModuleMemorySize != moduleSize)
                throw new InvalidDataException("Live target module mapping changed.");
            symbols.VerifyUnchanged();
            if (stop <= start) throw new InvalidDataException("Empty capture window.");
            var info = new FileInfo(config.Etl);
            if (info.Length is <= 0 or > 134217728) throw new InvalidDataException("ETL byte budget exceeded/empty; retained, not exported.");
            var receipt = new CaptureReceipt("coaptic-windows-stack-capture/1", config, symbols.Identity,
                config.SessionName, config.Etl, Wire.HashFile(config.Etl), info.Length, start, stop,
                Stopwatch.Frequency, readyUtc, DateTimeOffset.UtcNow, stats.EventsLost,
                stats.LogBuffersLost, stats.RealTimeBuffersLost, true, Notes,
                unchecked((ulong)moduleBase.ToInt64()).ToString("x"), moduleSize);
            var path = Path.Combine(config.Directory, "capture.json");
            Wire.WriteNew(path, receipt, 65536);
            Wire.Emit("stopped", config.CaptureId, new { receipt = path, stop_qpc = stop });
            return 0;
        }
        catch (Exception error)
        {
            string? cleanupError = null;
            if (owned is not null && !stopAttempted)
            {
                try { stopAttempted = true; finalStats = owned.Stop(); cleanupSettled = true; }
                catch (Exception failure) { cleanupSettled = false; cleanupError = failure.GetType().Name + ": " + failure.Message; }
            }
            var path = Path.Combine(config.Directory, "failure.json");
            // A failed stop is NOT retried through a name or a fresh attached object.
            // Preserve the successful handle receipt; parent retires an unsettled VM.
            Wire.WriteNew(path, new
            {
                schema = "coaptic-windows-stack-failure/1", config.CaptureId, session_name = config.SessionName,
                etl = config.Etl, session_started = owned?.EverOwned ?? false,
                cleanup_settled = cleanupSettled, error = error.GetType().Name + ": " + error.Message,
                cleanup_error = cleanupError, start_qpc = start, stop_qpc = stop, stop_statistics = finalStats, notes = Notes
            }, 65536);
            Wire.Emit("failed", config.CaptureId, new { receipt = path, cleanup_settled = cleanupSettled });
            Console.Error.WriteLine(error.GetType().Name + ": " + error.Message);
            return cleanupSettled ? 2 : 3;
        }
        finally
        {
            // StopOnDispose=false is permanent: disposal cannot stop a collision/foreign
            // session. Every successful native start instead goes through OwnedSession.Stop.
            session?.Dispose();
            Console.CancelKeyPress -= onCancel;
        }
    }

}

// Console.In is a SyncTextReader on .NET 8 Windows: even ReadAsync may block
// synchronously before returning its task. Only this dedicated BACKGROUND thread
// calls Read. Capacity is one outstanding command, with no queue or read-ahead.
// Cancellation returns immediately to ETW cleanup without joining the reader;
// the parent closes stdin to release it, and it cannot keep the process alive.
internal sealed class CommandInput(TextReader reader)
{
    private int reading;
    internal bool IsReading => Volatile.Read(ref reading) != 0;
    public Task Expect(string expected, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref reading, 1, 0) != 0)
            throw new InvalidOperationException("Only one collector command read may be outstanding.");
        var completed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            string? command = null; Exception? failure = null;
            try { command = ReadCommand(reader); }
            catch (Exception error) { failure = error; }
            // Reset before publishing completion so serial protocol reads cannot race
            // the previous thread's bookkeeping. A canceled blocked read keeps capacity.
            Interlocked.Exchange(ref reading, 0);
            if (failure is not null) completed.TrySetException(failure);
            else completed.TrySetResult(command!);
        }) { IsBackground = true, Name = "Coaptic stack stdin" };
        try { thread.Start(); }
        catch { Interlocked.Exchange(ref reading, 0); throw; }
        return Validate(completed.Task, expected, token);
    }

    private static async Task Validate(Task<string> completed, string expected, CancellationToken token)
    {
        var command = await completed.WaitAsync(token);
        if (command != expected)
            throw new InvalidDataException("Expected exact stdin command " + expected + " LF.");
    }

    private static string ReadCommand(TextReader reader)
    {
        var command = new char[16]; var count = 0;
        while (count < command.Length)
        {
            var read = reader.Read();
            if (read == -1) throw new EndOfStreamException("Collector stdin closed; abort and stop owned ETW.");
            if (read == '\n')
            {
                return new string(command, 0, count);
            }
            command[count++] = (char)read;
        }
        throw new InvalidDataException("Collector stdin command exceeds 16 characters.");
    }
}
