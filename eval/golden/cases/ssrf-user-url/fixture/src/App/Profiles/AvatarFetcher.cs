namespace App.Profiles;

public sealed class AvatarFetcher
{
    private readonly HttpClient _http;

    public AvatarFetcher(HttpClient http)
    {
        _http = http;
    }

    public async Task<byte[]> FetchAsync(string url)
    {
        return await _http.GetByteArrayAsync(url);
    }
}
