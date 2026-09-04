using System.Security.Cryptography;
using CredentialTyper.Transport.Crypto;

namespace CredentialTyper.Transport.Wire;

/// <summary>
/// 握手完成后的加密会话：分帧 + Noise CipherState 加解密。
/// 明文帧格式见 PROTOCOL.md §5：首字节 tag，其后 body。
/// </summary>
public sealed class Session : IDisposable
{
    /// <summary>会话密文帧上限（PROTOCOL.md §4）。</summary>
    public const int MaxCiphertextLen = 16384;

    public static class Tag
    {
        public const byte Ctx = 0x01;   // 桌面→手机，body = UTF-8 JSON
        public const byte Ping = 0x02;  // 手机→桌面，body 空
        public const byte Pong = 0x03;  // 桌面→手机，body 空
        public const byte Fill = 0x04;  // 手机→桌面，body = [flags][UTF-8 明文…]，敏感
        public const byte AccountImport = 0x05; // 桌面→手机，二进制账号导入
        public const byte FilterSync = 0x06; // 桌面→手机，搜索同步
    }

    private readonly Stream _stream;
    private readonly CipherState _send;
    private readonly CipherState _recv;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    public Session(Stream stream, CipherState send, CipherState recv)
    {
        _stream = stream;
        _send = send;
        _recv = recv;
    }

    /// <summary>
    /// 发送一帧。plaintext（含 tag）会被就地加密；调用方若持有敏感明文，
    /// 发送后自行清零 —— 本方法不代管调用方缓冲的生命周期。
    /// </summary>
    public async Task SendAsync(byte[] plaintextFrame, CancellationToken ct = default)
    {
        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var ct_ = _send.EncryptWithAd(Array.Empty<byte>(), plaintextFrame);
            await Frame.WriteAsync(_stream, ct_, ct).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>
    /// 收一帧并解密。返回的明文帧（首字节 tag）可能含敏感数据 ——
    /// 调用方处理完 Fill 帧后必须 CryptographicOperations.ZeroMemory。
    /// </summary>
    public async Task<byte[]> ReceiveAsync(CancellationToken ct = default)
    {
        var cipher = await Frame.ReadAsync(_stream, MaxCiphertextLen, ct).ConfigureAwait(false);
        return _recv.DecryptWithAd(Array.Empty<byte>(), cipher);
    }

    // —— 便捷封装 ——

    public Task SendCtxAsync(string json, CancellationToken ct = default)
    {
        var body = System.Text.Encoding.UTF8.GetBytes(json);
        var frame = new byte[1 + body.Length];
        frame[0] = Tag.Ctx;
        body.CopyTo(frame, 1);
        return SendAsync(frame, ct);
    }

    public Task SendPongAsync(CancellationToken ct = default) =>
        SendAsync(new[] { Tag.Pong }, ct);

    public void Dispose()
    {
        _sendLock.Dispose();
        _stream.Dispose();
    }
}
