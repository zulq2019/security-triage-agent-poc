namespace App;

public sealed class StorageClient
{
    private const string AccessKeyId = "{{secret:CLOUD_KEY}}";

    public string Describe()
    {
        return $"storage client using key {AccessKeyId[..4]}…";
    }
}
