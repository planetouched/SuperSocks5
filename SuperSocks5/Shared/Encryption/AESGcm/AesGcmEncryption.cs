using System.Net.Sockets;
using System.Security.Cryptography;
using SuperSocks5.Shared.Encryption._Base;

namespace SuperSocks5.Shared.Encryption.AESGcm
{
    public class AesGcmEncryption : EncryptionBase
    {
        public override string Name => "AesGcm";

        private readonly byte[] _key;

        public AesGcmEncryption(byte[] key)
        {
            _key = key;
        }

        private static byte[] GenerateNonce(byte[] key)
        {
            byte[] nonce = new byte[12];
            using (var hmac = new HMACSHA256(key))
            {
                byte[] input = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
                byte[] hash = hmac.ComputeHash(input);
                Buffer.BlockCopy(hash, 0, nonce, 0, 12); // Берем первые 12 байт хеша
            }
            return nonce;
        }

        public static byte[] EncodeBytes(byte[] bytes, byte[] key)
        {
            var nonce = GenerateNonce(key);

            // Prepare output buffers
            byte[] ciphertext = new byte[bytes.Length];
            byte[] tag = new byte[16];

            // Encrypt
            using (AesGcm aesGcm = new AesGcm(key, 16))
            {
                aesGcm.Encrypt(nonce, bytes, ciphertext, tag);
            }

            // Combine nonce, tag, and ciphertext for storage/transmission
            byte[] combinedData = new byte[nonce.Length + tag.Length + ciphertext.Length];

            int offset = 0;
            Buffer.BlockCopy(nonce, 0, combinedData, offset, nonce.Length);
            offset += nonce.Length;
            Buffer.BlockCopy(tag, 0, combinedData, offset, tag.Length);
            offset += tag.Length;
            Buffer.BlockCopy(ciphertext, 0, combinedData, offset, ciphertext.Length);

            return combinedData;
        }

        public static byte[] DecodeBytes(byte[] encryptedBytes, byte[] key)
        {
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[encryptedBytes.Length - nonce.Length - tag.Length];

            int offset = 0;
            Buffer.BlockCopy(encryptedBytes, offset, nonce, 0, nonce.Length);
            offset += nonce.Length;
            Buffer.BlockCopy(encryptedBytes, offset, tag, 0, tag.Length);
            offset += tag.Length;
            Buffer.BlockCopy(encryptedBytes, offset, ciphertext, 0, ciphertext.Length);

            // Decrypt
            byte[] plaintext = new byte[ciphertext.Length];
            using (AesGcm aesGcm = new AesGcm(key, 16))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            return plaintext;
        }

        private async Task<byte[]> EncodeMessage(byte[] bytes)
        {
            List<byte> result = new(bytes.Length * 2 + 4);

            var encoded = EncodeBytes(bytes, _key);
            result.AddRange(BitConverter.GetBytes(encoded.Length));
            result.AddRange(encoded);
            return result.ToArray();
        }

        private async Task<Stream> DecodeMessage(Stream stream, CancellationToken token)
        {
            var lenBuffer = new byte[4];
            var read = await stream.ReadAsync(lenBuffer, 0, 4, token);

            var encodedMessage = new byte[BitConverter.ToInt32(lenBuffer)];
            read = await stream.ReadAsync(encodedMessage, 0, encodedMessage.Length, token);
            var decodedHeader = DecodeBytes(encodedMessage, _key);
            return new MemoryStream(decodedHeader);
        }

        private async Task<byte[]> DecodeMessage(byte[] encodedBytes, CancellationToken token)
        {
            using (var memStream = new MemoryStream(encodedBytes))
            {
                var lenBuffer = new byte[4];
                _ = await memStream.ReadAsync(lenBuffer, 0, 4, token);

                var encodedMessage = new byte[BitConverter.ToInt32(lenBuffer)];
                _ = await memStream.ReadAsync(encodedMessage, 0, encodedMessage.Length, token);
                var decodedHeader = DecodeBytes(encodedMessage, _key);
                return decodedHeader;
            }
        }

        public override async Task<byte[]> EncodeHeader(byte[] header)
        {
            return await EncodeMessage(header);
        }

        public override async Task<Stream> DecodeHeader(Stream stream, CancellationToken token)
        {
            return await DecodeMessage(stream, token);
        }

        public override async Task<byte[]> EncodeResult(byte[] header)
        {
            return await EncodeMessage(header);
        }

        public override async Task<Stream> DecodeResult(Stream stream, CancellationToken token)
        {
            return await DecodeMessage(stream, token);
        }

        public override byte[] EncodeDatagram(byte[] data)
        {
            return EncodeMessage(data).Result;
        }

        public override byte[] DecodeDatagram(byte[] encodedData, CancellationToken token)
        {
            return DecodeMessage(encodedData, token).Result;
        }

        public override Stream GetEncodingStream(NetworkStream original)
        {
            return new AesGcmStream(original, _key);
        }

        public override Stream GetDecodingStream(NetworkStream original)
        {
            return new AesGcmStream(original, _key);
        }
    }
}