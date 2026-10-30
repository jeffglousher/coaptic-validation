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

    public bool Matches(TraceModuleFile file, ulong capturedBase) =>
        string.Equals(Path.GetFileName(file.FilePath), Path.GetFileName(config.Exe), StringComparison.OrdinalIgnoreCase) &&
        file.ImageBase == capturedBase && file.ImageSize == Identity.ImageSize &&
        (file.PdbSignature == Guid.Empty ? file.PdbAge == 0 :
            file.PdbSignature == Identity.PdbGuid && file.PdbAge == Identity.PdbAge) &&
        file.ImageId == Identity.ImageId && unchecked((uint)file.ImageChecksum) == Identity.ImageChecksum;

    public Frame Resolve(TraceCodeAddress address, ulong capturedBase)
    {
        var file = address.ModuleFile;
        var label = file is null ? "[unknown-module]" : file.FilePath;
        Wire.Text(label);
        var raw = address.Address.ToString("x");
        var name = "";
        if (file is not null && Matches(file, capturedBase) && address.Address >= file.ImageBase &&
            address.Address - file.ImageBase < (ulong)Identity.ImageSize)
            name = module.FindNameForRva(checked((uint)(address.Address - file.ImageBase)));
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
