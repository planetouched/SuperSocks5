namespace SuperSocks5.Shared.Encryption._Base
{
    public abstract class HandshakeEncryptionBase
    {
        public abstract string Name { get; }
        public abstract Task<byte[]> EncodeAuthRequest(byte[] data, CancellationToken token);
        public abstract Task<(Stream newStream, byte[]? newHeader)> DecodeAuthRequest(Stream stream, CancellationToken token);
        public abstract Task<byte[]> EncodeAuthResponse(byte[] data, CancellationToken token);
        public abstract Task<byte[]> DecodeAuthResponse(Stream stream, CancellationToken token);
    }
}
