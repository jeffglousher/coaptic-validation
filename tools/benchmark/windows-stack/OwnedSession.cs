using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing.Session;

namespace Coaptic.WindowsStack;

// The pinned public IsActive is false if TraceSetInformation fails after StartTrace.
// v3.1.21 TraceEventNativeMethods.StartTrace sets m_SessionHandle ONLY on native
// success (null on collision/error). This narrowly pinned adapter observes that proof
// of ownership, including partial starts. It never attaches, searches, or stops by name.
// Source: microsoft/perfview v3.1.21, TraceEventSession.cs and TraceEventNativeMethods.cs.
internal sealed class OwnedSession
{
    private readonly FieldInfo handleField;
    private readonly MethodInfo getHandle;
    private readonly TraceEventSession session;
    private readonly OwnedStop ownership = new();
    public bool EverOwned => ownership.EverOwned;
    public ulong? Handle => ownership.Handle;

    public OwnedSession(TraceEventSession session)
    {
        ValidatePin();
        this.session = session;
        handleField = typeof(TraceEventSession).GetField("m_SessionHandle", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new NotSupportedException("Pinned ownership field missing.");
        if (handleField.FieldType.FullName != "Microsoft.Diagnostics.Tracing.TraceEventNativeMethods+SafeTraceHandle")
            throw new NotSupportedException("Pinned ownership handle type changed.");
        getHandle = handleField.FieldType.GetMethod("DangerousGetHandle", BindingFlags.Public | BindingFlags.Instance,
            null, Type.EmptyTypes, null) ?? throw new NotSupportedException("Pinned handle accessor missing.");
        if (getHandle.ReturnType != typeof(ulong) || handleField.GetValue(session) is not null)
            throw new NotSupportedException("Expected a fresh pinned session with no native handle.");
        // Validate the ABI before any OS mutation. x64-only layout matches evntrace.h.
        if (Marshal.SizeOf<Properties>() != 120 || Marshal.OffsetOf<Properties>(nameof(Properties.EventsLost)).ToInt32() != 88)
            throw new NotSupportedException("Unexpected x64 ETW property layout.");
    }

    public static void ValidatePin()
    {
        var version = typeof(TraceEventSession).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion.Split('+')[0];
        if (version != "3.1.21") throw new NotSupportedException("Exactly TraceEvent 3.1.21 is required.");
        if (!Environment.Is64BitProcess) throw new NotSupportedException("x64 collector required.");
    }

    public ulong? ObserveStart()
    {
        var value = handleField.GetValue(session);
        if (value is null) return ownership.Observe(null); // No collision cleanup.
        var handle = (ulong)(getHandle.Invoke(value, null) ?? throw new InvalidDataException("Null native handle."));
        return ownership.Observe(handle);
    }

    public StopResult Stop()
    {
        ObserveStart();
        return ownership.Stop(StopNative);
    }

    private static StopResult StopNative(ulong handle)
    {
        // EVENT_TRACE_CONTROL_STOP flushes buffers and returns final statistics. Do not
        // call TraceEventSession.Stop(): the pinned implementation controls by NAME,
        // also resets the machine-global sampling interval, and marks stopped before
        // OS success. Retain failure evidence instead of claiming cleanup succeeded.
        var memory = Marshal.AllocHGlobal(8192);
        try
        {
            Marshal.Copy(new byte[8192], 0, memory, 8192);
            var properties = new Properties
            {
                Wnode = new Wnode { BufferSize = 8192 },
                LoggerNameOffset = 120,
                LogFileNameOffset = 120 + 2048
            };
            Marshal.StructureToPtr(properties, memory, false);
            var error = ControlTrace(handle, null, memory, 1);
            if (error != 0) throw new Win32Exception(checked((int)error), "Owned ETW handle stop/flush failed.");
            properties = Marshal.PtrToStructure<Properties>(memory);
            return new(true, properties.EventsLost, properties.LogBuffersLost, properties.RealTimeBuffersLost);
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    internal sealed record StopResult(bool Started, uint EventsLost, uint LogBuffersLost, uint RealTimeBuffersLost);
    [DllImport("advapi32.dll", EntryPoint = "ControlTraceW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint ControlTrace(ulong handle, string? name, IntPtr properties, uint controlCode);

    [StructLayout(LayoutKind.Sequential)]
    private struct Wnode
    {
        public uint BufferSize, ProviderId;
        public ulong HistoricalContext, TimeStamp;
        public Guid Guid;
        public uint ClientContext, Flags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Properties
    {
        public Wnode Wnode;
        public uint BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode, FlushTimer, EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset, LoggerNameOffset;
    }
}

// Pure state shared by production cleanup and self-tests. The input is exclusively
// the pinned StartTrace successful-handle field, never an active-session query.
internal sealed class OwnedStop
{
    public ulong? Handle { get; private set; }
    public bool EverOwned => Handle.HasValue;
    private bool attempted;
    public ulong? Observe(ulong? successfulHandle)
    {
        if (!successfulHandle.HasValue)
        {
            if (Handle.HasValue) throw new InvalidDataException("Successful owned handle disappeared.");
            return null;
        }
        if (successfulHandle.Value is 0 or ulong.MaxValue || Handle.HasValue && Handle != successfulHandle)
            throw new InvalidDataException("Invalid or changed successful-start handle.");
        return Handle = successfulHandle;
    }
    public OwnedSession.StopResult Stop(Func<ulong, OwnedSession.StopResult> stop)
    {
        if (attempted) throw new InvalidOperationException("Owned stop already attempted; no name-based retry.");
        attempted = true;
        return Handle.HasValue ? stop(Handle.Value) : new(false, 0, 0, 0);
    }
}
