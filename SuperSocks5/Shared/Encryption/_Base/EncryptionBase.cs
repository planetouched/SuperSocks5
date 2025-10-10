using System.Net.Sockets;

namespace SuperSocks5.Shared.Encryption._Base;

public abstract class EncryptionBase
{
    public abstract string Name { get; }
    public abstract Task<byte[]> EncodeHeader(byte[] header);
    public abstract Task<Stream> DecodeHeader(Stream stream, CancellationToken token);

    public abstract Task<byte[]> EncodeResult(byte[] header);
    public abstract Task<Stream> DecodeResult(Stream stream, CancellationToken token);

    public abstract byte[] EncodeDatagram(byte[] data);
    public abstract byte[] DecodeDatagram(byte[] encodedData, CancellationToken token);

    public abstract Stream GetEncodingStream(NetworkStream original);
    public abstract Stream GetDecodingStream(NetworkStream original);
}