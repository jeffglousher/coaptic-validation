using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing.Session;

namespace Coaptic.WindowsStack;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "metadata")
            {
                OwnedSession.ValidatePin();
                Wire.Emit("metadata", Guid.Empty, new
                {
                    tool = Wire.Tool, trace_event_version = "3.1.21", runtime = RuntimeInformation.FrameworkDescription,
                    os = RuntimeInformation.OSDescription, architecture = RuntimeInformation.ProcessArchitecture.ToString(),
                    capture_schema = "coaptic-windows-stack-capture/1", export_schema = "coaptic-stack-profile/1",
                    protocol = "armed/start/ready/stop/stopped; stop includes flush; EOF aborts with explicit owned-handle stop",
                    max_export_bytes = Wire.ExportLimit, max_stack_depth = 128, max_stacks = 100000, max_frames = 200000,
                    capture_notes = Capture.Notes
                });
                return 0;
            }
            if (args.Length == 1 && args[0] == "selftest") return SelfTests.Run();
            if (args.Length == 3 && args[0] == "target" && args[1] == "--pid")
            {
                var pid = int.Parse(args[2], CultureInfo.InvariantCulture);
                using var process = Process.GetProcessById(pid);
                var ids = new List<int>();
                foreach (ProcessThread thread in process.Threads)
                {
                    using (thread) ids.Add(thread.Id);
                    if (ids.Count > 128) throw new InvalidDataException("Target thread inventory exceeds 128.");
                }
                ids.Sort();
                Wire.Emit("target", Guid.Empty, new
                {
                    pid, process_start_utc = process.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                    exe = process.MainModule?.FileName ?? throw new InvalidDataException("Target EXE path missing."),
                    thread_ids = ids, main_thread_id = ids.Count == 1 ? (int?)ids[0] : null
                });
                return 0;
            }
            if (args.Length != 3 || args[1] != "--config")
                throw new ArgumentException("Usage: metadata | selftest | target --pid PID | symbols|preflight|capture|export --config ABSOLUTE_JSON");
            if (args[0] == "export") return Export.Run(Wire.Read<ExportConfig>(args[2]));
            if (args[0] is not ("symbols" or "preflight" or "capture")) throw new ArgumentException("Unknown command.");
            var config = Wire.Read<CaptureConfig>(args[2]);
            if (args[0] == "capture") return await Capture.Run(config);
            config.Validate(); OwnedSession.ValidatePin();
            if (args[0] == "preflight") Capture.HostedPreflight(config);
            using var symbols = new OwnedSymbols(config);
            if (args[0] == "symbols")
            {
                Wire.Emit("symbols", config.CaptureId, new { tool = Wire.Tool, image = symbols.Identity });
                return 0;
            }
            using var target = Capture.ValidateTarget(config);
            // Validate the exact private adapter and ABI without enabling any provider.
            using (var session = new TraceEventSession(config.SessionName, config.Etl,
                TraceEventSessionOptions.Create | TraceEventSessionOptions.NoRestartOnCreate))
            {
                session.StopOnDispose = false;
                _ = new OwnedSession(session);
            }
            Wire.Emit("preflight", config.CaptureId, new
            {
                tool = Wire.Tool, image = symbols.Identity, config.Pid, config.Tid,
                process_start_utc = config.ProcessStartUtc.ToString("O", CultureInfo.InvariantCulture),
                hosted = true, administrator = true
            });
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.GetType().Name + ": " + error.Message);
            return 2;
        }
    }
}
