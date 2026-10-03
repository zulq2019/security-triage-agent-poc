using SecAgent.Core;

namespace SecAgent.Intake.Storage;

/// <summary>Raw payloads in the local Blob stand-in (container "raw", write-once, sha256-hashed), the same store the scanners use.
/// Azure: implement <see cref="IRawFindingStore"/> over Azure.Storage.Blobs (container "raw", immutability policy, managed identity);
/// the uri scheme stays blob://raw/… so evidence references do not change.</summary>
public sealed class LocalRawFindingStore(LocalBlobStore blob) : IRawFindingStore
{
    public const string Container = "raw";
    public RawRef Put(string path, byte[] content)
    {
        var (uri, hash) = blob.Put(Container, path, content);
        return new RawRef(uri, hash);
    }
    public byte[] Get(string uri) => File.ReadAllBytes(blob.ResolvePath(uri));
}
