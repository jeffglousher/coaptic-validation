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
        AttributionTests();
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

    private static void AttributionTests()
    {
        var guid = Guid.Parse("9ca23107-0be2-4350-8416-05e83dd701b8");
        var image = new ImageIdentity("owned-exe-hash", "owned-pdb-hash", guid, 1, 0x6ae43917, 4096, 0);
        var mapping = new NativeMapping(132, 1334, "C:/owned/bench-core.exe", 0x10000, 4096, 90, 210);
        ModuleAttribution New(bool live = true, ImageIdentity? expected = null, ulong address = 0x10000) =>
            new(expected ?? image, 4936, 132, "bench-core.exe", address, 100, 200, 1000, 100, 200, live);
        ModuleAttribution Selected(int timestamp = 0, uint checksum = 0, Guid? debug = null, int age = 0)
        {
            var model = New();
            model.SelectMapping(new[] { mapping });
            model.ObserveAggregate(timestamp, checksum, debug ?? Guid.Empty, age);
            return model;
        }
        void Kernel(ModuleAttribution model, int timestamp = 0, uint checksum = 0, long qpc = 90,
            int opcode = 3, bool header = true, ulong address = 0x10000, string path = "C:/owned/bench-core.exe")
        {
            model.CountEvent();
            model.ObserveKernel(4936, qpc, opcode, address, 4096, path, header, timestamp, checksum);
        }
        ModuleBinding Finish(ModuleAttribution model)
        {
            model.CompleteScan(true);
            return model.Finish(false);
        }
        var zero = Selected(); Kernel(zero); Kernel(zero, qpc: 210, opcode: 4);
        var binding = Finish(zero);
        Check(zero.AggregateImageIdStatus == "unavailable-recorded-zero" && !zero.NonzeroImageIdMatched &&
            zero.AggregateDebugIdStatus == "unavailable-recorded-empty" && zero.RawDebugIdStatus == "absent",
            "recorded zero and absent DebugID never reported matched");
        Refuses(() => New(false), "zero requires independent live owned binding");
        Refuses(() => New(expected: image with { PdbGuid = Guid.Empty }), "live binding requires exact local PDB identity");
        Check(binding.TryRva(132, 100, 1334, 0x10000, out var first) && first == 0 &&
            binding.TryRva(132, 199, 1334, 0x10fff, out var last) && last == 4095, "selected RVA and window edges");
        Check(!binding.TryRva(132, 99, 1334, 0x10000, out _) &&
            !binding.TryRva(132, 200, 1334, 0x10000, out _) &&
            !binding.TryRva(132, 150, 1334, 0xffff, out _) &&
            !binding.TryRva(132, 150, 1334, 0x11000, out _), "outside window/range unresolved without subtraction underflow");
        Check(!binding.TryRva(133, 150, 1334, 0x10000, out _) &&
            !binding.TryRva(132, 150, 1335, 0x10000, out _), "shared code address and wrong module index cannot authorize lookup");
        Refuses(() => ModuleAttribution.RequireUniqueLifetime(2), "PID/TID reuse refused");
        Refuses(() => ModuleAttribution.RequireUniqueLifetime(0), "missing PID/TID refused");
        foreach (var other in new[] { mapping, mapping with { ModuleIndex = 1335 },
            mapping with { Base = 0xff00, Path = "C:/other/wrong.dll" },
            mapping with { Base = 0x10800, Path = "C:/other/wrong.dll" },
            mapping with { Base = 0x10800, Size = 0, Path = "C:/other/wrong.dll" },
            mapping with { Base = 0x20000, Size = 2 } })
            Refuses(() => New().SelectMapping(new[] { mapping, other }), "all relevant candidates counted before metadata");
        foreach (var bad in new[] { mapping with { LoadMSec = 101 }, mapping with { UnloadMSec = 199 },
            mapping with { LoadMSec = double.NaN }, mapping with { UnloadMSec = double.PositiveInfinity },
            mapping with { ProcessIndex = 133 }, mapping with { ModuleIndex = -1 },
            mapping with { Size = 4095 }, mapping with { Path = "C:/wrong.exe" } })
            Refuses(() => New().SelectMapping(new[] { bad }), "invalid or partial selected mapping");
        Refuses(() => New(address: ulong.MaxValue - 100), "owned address range overflow");
        Check(!ModuleAttribution.ValidRange(1, 0) && !ModuleAttribution.ValidRange(1, -1), "invalid image sizes");
        var overflowingRva = binding with { Mapping = mapping with { Base = 1, Size = (long)uint.MaxValue + 2 } };
        Check(!overflowingRva.TryRva(132, 150, 1334, (ulong)uint.MaxValue + 2, out _), "RVA uint overflow refused");
        Check(ModuleAttribution.ImageIdStatus(0, 0, true) == "unavailable-recorded-zero" &&
            ModuleAttribution.ImageIdStatus(0, image.ImageId, false) == "refused-no-live-binding",
            "zero is never corroboration even when expected timestamp is zero");
        var matched = Selected(image.ImageId, debug: guid, age: 1);
        Kernel(matched, image.ImageId); Finish(matched);
        Check(matched.AggregateImageIdStatus == "matched" && matched.NonzeroImageIdMatched &&
            matched.AggregateDebugIdStatus == "matched", "nonzero exact corroboration reported matched");
        var contradiction = Selected();
        Kernel(contradiction, 123); Kernel(contradiction); Kernel(contradiction, image.ImageId);
        Refuses(() => Finish(contradiction), "earlier raw contradiction survives zero and match");
        var aggregateWrong = Selected(123); Kernel(aggregateWrong, image.ImageId);
        Refuses(() => Finish(aggregateWrong), "raw match cannot erase aggregate contradiction");
        foreach (var aggregate in new[] { true, false })
        {
            var badChecksum = Selected(checksum: aggregate ? 1u : 0u);
            Kernel(badChecksum, checksum: aggregate ? 0u : 1u);
            Refuses(() => Finish(badChecksum), "checksum exact including expected zero");
        }
        var nonzeroChecksum = New(expected: image with { ImageChecksum = 1 });
        nonzeroChecksum.SelectMapping(new[] { mapping });
        nonzeroChecksum.ObserveAggregate(0, 1, Guid.Empty, 0); Kernel(nonzeroChecksum);
        Refuses(() => Finish(nonzeroChecksum), "recorded zero checksum cannot replace expected nonzero");
        foreach (var (debug, age) in new[] { (Guid.Empty, 1), (guid, 0), (guid, 2), (Guid.NewGuid(), 1) })
        {
            var bad = Selected(debug: debug, age: age); Kernel(bad);
            Refuses(() => Finish(bad), "aggregate GUID/age contradiction");
            var rawBad = Selected(); Kernel(rawBad);
            rawBad.ObserveDebugId(4936, 0x10000, debug, age);
            rawBad.ObserveDebugId(4936, 0x10000, Guid.Empty, 0);
            rawBad.ObserveDebugId(4936, 0x10000, guid, 1);
            Refuses(() => Finish(rawBad), "raw GUID/age contradiction sticky");
        }
        var rawDebug = Selected(); Kernel(rawDebug);
        rawDebug.ObserveDebugId(4936, 0x10000, Guid.Empty, 0);
        Check(rawDebug.RawDebugIdStatus == "unavailable-recorded-empty", "empty raw DebugID not matched");
        rawDebug.ObserveDebugId(4936, 0x10000, guid, 1); Finish(rawDebug);
        Check(rawDebug.RawDebugIdStatus == "matched", "actual exact raw DebugID matched");
        var synthetic = Selected(); Kernel(synthetic);
        synthetic.ObserveImageId(4936, 0x10000, 4096, "bench-core.exe", 123);
        synthetic.ObserveImageId(4936, 0x10000, 4096, "bench-core.exe", 0);
        synthetic.ObserveImageId(4936, 0x10000, 4096, "bench-core.exe", image.ImageId);
        Refuses(() => Finish(synthetic), "synthetic ImageID contradiction survives zero/match");
        var ambiguous = Selected(); Kernel(ambiguous);
        ambiguous.ObserveDebugId(0, 0x10000, guid, 1);
        Refuses(() => Finish(ambiguous), "synthetic shared base without PID refuses attribution");
        foreach (var opcode in new[] { 10, 2 })
        foreach (var qpc in new long[] { 100, 150, 199 })
        {
            var transition = Selected(); Kernel(transition, opcode: opcode, qpc: qpc);
            Refuses(() => Finish(transition), "actual transition inside window refuses");
        }
        var transitions = Selected(); Kernel(transitions, opcode: 10); Kernel(transitions, opcode: 2, qpc: 200);
        var timed = Finish(transitions);
        Check(timed.LoadQpc == 90 && timed.UnloadQpc == 200 && timed.TryRva(132, 199, 1334, 0x10001, out _),
            "raw actual bounds used when available");
        Check(binding.LoadQpc is null && binding.UnloadQpc is null, "rundown observations are not transitions");
        var observation = Selected(); Kernel(observation, qpc: 150); Kernel(observation, qpc: 160, opcode: 4);
        Finish(observation);
        Check(observation.Contradiction is null, "rundown inside window is only an observation");
        var rawMapping = Selected(); Kernel(rawMapping, address: 0x10800, path: "C:/other/wrong.dll"); Kernel(rawMapping);
        Refuses(() => Finish(rawMapping), "raw overlapping mapping cannot hide behind later correct metadata");
        var unrelated = Selected(); Kernel(unrelated);
        unrelated.ObserveKernel(99, 150, 10, 0x10000, 4096, "bench-core.exe", true, 123, 1);
        unrelated.ObserveImageId(99, 0x10000, 4096, "bench-core.exe", 123);
        unrelated.ObserveDebugId(99, 0x10000, Guid.Empty, 1);
        unrelated.ObserveKernel(4936, 150, 10, 0x30000, 4096, "other.dll", true, 123, 1);
        Finish(unrelated);
        Check(unrelated.Contradiction is null, "unrelated process and nonoverlapping modules do not authorize or contaminate binding");
        var lateContradiction = Selected();
        for (var i = 0; i < 40; i++) Kernel(lateContradiction);
        Kernel(lateContradiction, 123);
        Refuses(() => Finish(lateContradiction), "validation continues beyond 32 diagnostic rows");
        var absent = Selected(); Kernel(absent, header: false); Finish(absent);
        Check(absent.RawHeaderAbsent && !absent.RecordedZeroImageId &&
            absent.AggregateImageIdStatus == "unavailable-aggregate-zero", "absent versioned fields not reported recorded zero");
        var incomplete = Selected(); Kernel(incomplete);
        Refuses(() => incomplete.Finish(false), "uncompleted scan refuses");
        incomplete.CompleteScan(false);
        Refuses(() => Finish(incomplete), "incomplete scan remains refused after later completion");
        var truncated = Selected(); Kernel(truncated); truncated.CompleteScan(true);
        Refuses(() => truncated.Finish(true), "conversion truncation refuses");
        var overflow = Selected(); Kernel(overflow);
        for (var i = 1; i < 1_000_000; i++) overflow.CountEvent();
        Check(overflow.EventsInspected == 1_000_000, "exact raw event budget retained");
        Refuses(overflow.CountEvent, "one-million raw event budget exceeded");
        Refuses(() => Finish(overflow), "event overflow remains refused");
        var noRaw = Selected(); noRaw.CountEvent(); noRaw.CompleteScan(true);
        Refuses(() => noRaw.Finish(false), "complete stream without target kernel mapping refuses");
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
