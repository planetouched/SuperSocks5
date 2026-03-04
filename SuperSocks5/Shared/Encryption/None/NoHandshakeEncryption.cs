using SuperSocks5.Shared.Encryption._Base;

namespace SuperSocks5.Shared.Encryption.None;

public class NoHandshakeEncryption : HandshakeEncryptionBase
{
    public const string StaticName = "No";
    public override string Name => StaticName;

    public override async Task<byte[]> EncodeAuthRequest(byte[] data, CancellationToken token)
    {
        return data;
    }

    public override async Task<(Stream newStream, byte[]? newHeader)> DecodeAuthRequest(Stream stream, CancellationToken token)
    {
        return (stream, null);
    }

    public override async Task<byte[]> EncodeAuthResponse(byte[] data, CancellationToken token)
    {
        return data;
    }

    public override async Task<byte[]> DecodeAuthResponse(Stream stream, CancellationToken token)
    {
        var handshakeResponse = new byte[2];
        await stream.ReadExactlyAsync(handshakeResponse, 0, 2, token);
        return handshakeResponse;
    }

    public static bool Detect(byte id)
    {
        return id == S5Const.Version;
    }
}