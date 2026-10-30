namespace Coaptic.WindowsStack;

// Pure model tests: no ETW sessions, native captures, PDB loads, external files or
// build output. Real native Rust caller ancestry and ETW failure tests belong to
// the parent's dedicated ephemeral hosted qualification, not this test claim.
internal static class SelfTests
{
    private static int passed;
    private static void Check(bool ok, string name)
    {
        if (!ok) throw new InvalidOperationException("Selftest failed: " + name);
        passed++;
    }
    private static void Refuses(Action action, string name)
    {
        try { action(); }
        catch (InvalidDataException) { passed++; return; }
        throw new InvalidOperationException("Selftest did not refuse: " + name);
    }
    public static int Run()
    {
        passed = 0;
        var identity = new Identity("source", "tool", "workload", "capture", "platform", "cohort");
        var samples = new Samples(11, 22, 100, 200, 1000);
        Check(samples.InScope(11, 22, 100) && !samples.InScope(11, 22, 200), "half-open window");
        Check(!samples.InScope(12, 22, 150), "wrong PID excluded");
        Check(!samples.InScope(11, 23, 150), "wrong TID excluded");
        Check(!samples.InScope(11, 22, 99), "before window excluded");
        samples.Add(22, 150, "bench-core", new()
        {
            new("leaf", "30", "owned.exe", false), new("caller", "20", "owned.exe", false),
            new("root", "10", "owned.exe", false)
        }, false);
        var profile = samples.Finish(identity, "one", 7, "loss retained");
        Check(profile.Stacks[0].Frames.SequenceEqual(new[] { "root", "caller", "leaf" }), "known caller chain root-to-leaf");
        Check(profile.Stacks[0].Event.Addresses.SequenceEqual(new[] { "10", "20", "30" }), "addresses aligned");
        Check(profile.Quality.Lost == 7 && profile.Totals.Samples == 1 && profile.Totals.Weight == 1, "loss not subtracted or hidden");
        var guid = Guid.Parse("4d14e9aa-ea74-47e8-a581-c75e7f4a6e74");
        OwnedSymbols.RequireMatch(guid, 1, guid, 1); passed++;
        Refuses(() => OwnedSymbols.RequireMatch(guid, 1, Guid.Empty, 1), "missing PDB identity");
        Refuses(() => OwnedSymbols.RequireMatch(guid, 1, Guid.NewGuid(), 1), "mismatched PDB GUID");
        Refuses(() => OwnedSymbols.RequireMatch(guid, 1, guid, 2), "mismatched PDB age");
        var mixed = new Samples(11, null, 100, 200, 1000);
        mixed.Add(22, 150, "bench", new() { new("leaf", "1", "owned.exe", false) }, false);
        Check(mixed.InScope(11, 23, 151), "unselected TID still reaches mixed-thread refusal");
        Refuses(() => mixed.Add(23, 151, "bench", new() { new("leaf", "1", "owned.exe", false) }, false), "mixed TIDs");
        Refuses(() => new Samples(11, 22, 100, 200, 1000).Finish(identity, "one", 0, "empty"), "empty profile");
        var unresolved = new Samples(11, 22, 100, 200, 1000);
        unresolved.Add(22, 150, "bench", new() { new("[missing-stack]", "0", "[unknown-module]", true) }, true);
        Check(unresolved.Finish(identity, "one", 0, "truncated").Quality.Unresolved == 1 && unresolved.Truncated == 1,
            "unresolved and truncation retained");
        var collision = new OwnedStop(); var stopped = new List<ulong>();
        collision.Observe(null);
        collision.Stop(h => { stopped.Add(h); return new(true, 0, 0, 0); });
        Check(stopped.Count == 0 && !collision.EverOwned, "collision cannot stop foreign session");
        var partial = new OwnedStop(); partial.Observe(123);
        partial.Stop(h => { stopped.Add(h); return new(true, 0, 0, 0); });
        Check(stopped.SequenceEqual(new ulong[] { 123 }), "partial start/cancel stops only successful owned handle");
        var failed = new OwnedStop(); failed.Observe(456);
        Refuses(() => failed.Stop(_ => throw new InvalidDataException("simulated native stop failure")), "stop failure preserved");
        Refuses(() => new OwnedStop().Observe(ulong.MaxValue), "invalid start handle");
        Refuses(() => { var changed = new OwnedStop(); changed.Observe(1); changed.Observe(2); }, "changed handle refused");
        foreach (var path in new[]
        {
            @"\\server\share\capture.etl", "//server/share/capture.etl", @"\\?\C:\capture.etl",
            "//?/C:/capture.etl", @"\\.\PhysicalDrive0", @"\??\C:\capture.etl",
            "C:relative.etl", "/rooted/capture.etl", "C:/capture.etl:stream", @"C:\NUL",
            @"C:\CON.txt", @"D:\capture.\file.etl",
            "C:/owned/COM\u00b9", "C:/owned/COM\u00b2.txt", "C:/owned/COM\u00b3",
            "C:/owned/LPT\u00b9.txt", "C:/owned/LPT\u00b2", "C:/owned/LPT\u00b3.txt"
        }) Refuses(() => Wire.NormalizeLocalPath(path), "raw UNC/device/relative/ADS/ambiguous path: " + path);
        Check(Wire.NormalizeLocalPath("C:/owned/sub/../capture.etl") == @"C:\owned\capture.etl",
            "ordinary slash drive path normalized without filesystem queries");
        Check(Wire.NormalizeLocalPath(@"D:\owned\capture.etl") == @"D:\owned\capture.etl",
            "ordinary backslash drive path accepted");
        var control = new CommandInput(new StringReader("start\nstop\n"));
        control.Expect("start", CancellationToken.None).GetAwaiter().GetResult();
        control.Expect("stop", CancellationToken.None).GetAwaiter().GetResult();
        Check(!control.IsReading, "serial start/stop control without read-ahead");
        Refuses(() => new CommandInput(new StringReader("wrong\n")).Expect("start", CancellationToken.None)
            .GetAwaiter().GetResult(), "invalid control command");
        Refuses(() => new CommandInput(new StringReader(new string('x', 16))).Expect("start", CancellationToken.None)
            .GetAwaiter().GetResult(), "bounded control command length");
        using (var reader = new WithheldInput())
        using (var cancel = new CancellationTokenSource())
        {
            var withheld = new CommandInput(reader);
            var pending = withheld.Expect("stop", cancel.Token);
            try
            {
                Check(reader.Started.Wait(TimeSpan.FromSeconds(5)), "withheld input read started");
                Check(reader.Background, "blocking input thread is background");
                cancel.Cancel();
                var canceled = false;
                try { pending.GetAwaiter().GetResult(); }
                catch (OperationCanceledException) { canceled = true; }
                Check(canceled && withheld.IsReading, "control cancellation completes while reader remains blocked");
                var duplicateRefused = false;
                try { _ = withheld.Expect("stop", CancellationToken.None); }
                catch (InvalidOperationException) { duplicateRefused = true; }
                Check(duplicateRefused, "canceled outstanding reader retains single-command capacity");
                var active = new OwnedStop(); active.Observe(789);
                active.Stop(h => { stopped.Add(h); return new(true, 0, 0, 0); });
                Check(stopped[^1] == 789, "owned cleanup proceeds before blocked input is released");
            }
            finally { reader.Release.Set(); }
            Check(reader.Exited.Wait(TimeSpan.FromSeconds(5)), "parent EOF releases blocking reader");
        }
        Wire.Emit("selftest", Guid.Empty, new { passed, native_capture = false, pdb_io = false, qualification = "pure models only" });
        return 0;
    }

    private sealed class WithheldInput : TextReader
    {
        public ManualResetEventSlim Started { get; } = new();
        public ManualResetEventSlim Release { get; } = new();
        public ManualResetEventSlim Exited { get; } = new();
        public bool Background { get; private set; }
        public override int Read()
        {
            try
            {
                Background = Thread.CurrentThread.IsBackground;
                Started.Set();
                if (!Release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Withheld-input model did not release.");
                return -1;
            }
            finally { Exited.Set(); }
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Release.Set();
                // No wait is required in production cancellation cleanup. This test
                // releases its own pure model before disposing its synchronization.
                if (Started.IsSet) Exited.Wait(TimeSpan.FromSeconds(5));
                Started.Dispose(); Release.Dispose(); Exited.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
