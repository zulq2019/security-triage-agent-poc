using System.Net;
using App.Profiles;
using Xunit;

namespace App.Tests;

public sealed class FakeHandler : HttpMessageHandler
{
    public List<Uri> Requests { get; } = new();

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request.RequestUri!);
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 1, 2, 3 }) });
    }
}

public class AvatarFetcherTests
{
    [Fact]
    public async Task Fetches_an_avatar_from_the_avatar_host()
    {
        var handler = new FakeHandler();
        var bytes = await new AvatarFetcher(new HttpClient(handler)).FetchAsync("https://avatars.example.com/u/1.png");
        Assert.Equal(3, bytes.Length);
    }
}
