using System.Text;
using CredentialTyper.Transport.Wire;

namespace CredentialTyper.Transport.Tests;

public sealed class AccountImportFrameTests
{
    [Fact]
    public void FilterSyncRoundTrips()
    {
        var frame = FilterSyncFrame.Encode("ChatGPT.exe");
        Assert.Equal("ChatGPT.exe", FilterSyncFrame.Decode(frame));
    }

    [Fact]
    public void RoundTripPreservesFields()
    {
        var frame = AccountImportFrame.Encode("GitHub", "u@example.com", "https://www.example.com/login", "note", Encoding.UTF8.GetBytes("pw"));
        var decoded = AccountImportFrame.Decode(frame);
        Assert.Equal("example.com", decoded.Website);
        Assert.Equal("GitHub", decoded.Title);
        Assert.Equal("pw", Encoding.UTF8.GetString(decoded.Password));
    }

    [Fact]
    public void RejectsLengthMismatch()
    {
        var frame = AccountImportFrame.Encode("a", "b", "c.com", "", Array.Empty<byte>());
        frame = frame[..^1];
        Assert.Throws<FormatException>(() => AccountImportFrame.Decode(frame));
    }
}
