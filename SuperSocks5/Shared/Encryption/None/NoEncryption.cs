using System.Net.Sockets;
using SuperSocks5.Shared.Encryption._Base;

namespace SuperSocks5.Shared.Encryption.None
{
    public class NoEncryption : EncryptionBase
    {
        public override string Name => "No";

        public override async Task<byte[]> EncodeHeader(byte[] header)
        {
            return header;
        }

        public override async Task<Stream> DecodeHeader(Stream stream, CancellationToken token)
        {
            return stream;
        }

        public override async Task<byte[]> EncodeResult(byte[] header)
        {
            return header;
        }

        public override async Task<Stream> DecodeResult(Stream stream, CancellationToken token)
        {
            return stream;
        }

        public override byte[] EncodeDatagram(byte[] data)
        {
            return data;
        }

        public override byte[] DecodeDatagram(byte[] encodedData, CancellationToken token)
        {
            return encodedData;
        }
        
        public override Stream GetEncodingStream(NetworkStream original)
        {
            return original;
        }

        public override Stream GetDecodingStream(NetworkStream original)
        {
            return original;
        }
    }
}
