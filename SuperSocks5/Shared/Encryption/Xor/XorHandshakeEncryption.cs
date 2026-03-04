using SuperSocks5.Shared.Encryption._Base;

namespace SuperSocks5.Shared.Encryption.Xor;

public class XorHandshakeEncryption : HandshakeEncryptionBase
{
    public const string StaticName = "Xor";
    public override string Name => StaticName;

    public const int MinInclusive = 6;
    public const int MaxExclusive = 30;

    public override async Task<byte[]> EncodeAuthRequest(byte[] data, CancellationToken token)
    {
        return XorUtil.EncodeMessage1(data);
    }

    public override async Task<(Stream newStream, byte[]? newHeader)> DecodeAuthRequest(Stream stream, CancellationToken token)
    {
        var newStream = await XorUtil.DecodeStream1(stream, true, token);
        var newRequestHeader = new byte[2];
        await newStream.ReadExactlyAsync(newRequestHeader, 0, newRequestHeader.Length, token);
        return (newStream, newRequestHeader);
    }

    public override async Task<byte[]> EncodeAuthResponse(byte[] data, CancellationToken token)
    {
        return XorUtil.EncodeMessage1(data);
    }

    public override async Task<byte[]> DecodeAuthResponse(Stream stream, CancellationToken token)
    {
        return await XorUtil.DecodeMessage1(stream, false, token);
    }

    public static bool Detect(byte id)
    {
        return id >= MinInclusive && id < MaxExclusive;
    }    
}