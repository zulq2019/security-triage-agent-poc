using Microsoft.Extensions.DependencyInjection;
using SecAgent.Abstractions.Intake;
using SecAgent.Core;

namespace SecAgent.Intake.Storage;

/// <summary>Local adapter for <see cref="IRawFindingStore"/>: the write-once local blob store (container "raw", sha256-hashed), the same
/// folder layout the scanners use. The Azure adapter (SecAgent.Intake.Azure) keeps the blob://raw/… URI scheme.</summary>
public sealed class LocalRawFindingStore([FromKeyedServices(LocalRawFindingStore.BlobStoreKey)] LocalBlobStore blob) : IRawFindingStore
{
    public const string Container = "raw";
    /// <summary>DI key of the <see cref="LocalBlobStore"/> this adapter writes to (rooted at Intake:RawStoreRoot).</summary>
    public const string BlobStoreKey = "intake-raw";

    public RawRef Put(string path, byte[] content)
    {
        var (uri, hash) = blob.Put(Container, path, content);
        return new RawRef(uri, hash);
    }
    public byte[] Get(string uri) => File.ReadAllBytes(blob.ResolvePath(uri));
}
