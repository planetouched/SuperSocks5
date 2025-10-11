using SuperSocks5.Shared.Encryption._Base;
using System.Net.Sockets;
using System.Text;

namespace SuperSocks5.Shared.Encryption.AESGcm
{
    public class AesGcmKeyTimeCredentials : AuthCredentialsBase
    {
        private readonly byte[] _key;
        private readonly string _keyPhrase;
        private readonly int _expiredTimeMs;

        public AesGcmKeyTimeCredentials(string keyPhrase, byte[] key, int expiredTimeMs = 5000) : base(0x84)
        {
            _expiredTimeMs = expiredTimeMs;
            _keyPhrase = keyPhrase;
            _key = key;
        }

        public override async Task<bool> Authenticate(NetworkStream stream, CancellationToken token)
        {
            var message = new List<byte>();

            message.Add(0x01);

            long unixTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var keyPhraseBytes = Encoding.UTF8.GetBytes(_keyPhrase);
            var buff = new byte[8 + keyPhraseBytes.Length];
            Buffer.BlockCopy(BitConverter.GetBytes(unixTimeMs), 0, buff, 0, 8);
            Buffer.BlockCopy(keyPhraseBytes, 0, buff, 8, keyPhraseBytes.Length);
            var encodedBytes = AesGcmEncryption.EncodeBytes(buff, _key);

            message.Add((byte)encodedBytes.Length);
            message.AddRange(encodedBytes);

            await stream.WriteAsync(message.ToArray(), 0, message.Count, token);

            /*
            +----+--------+
            |VER | STATUS |
            +----+--------+
            | 1  |   1    |
            +----+--------+
            */

            var authResponse = new byte[2];

            var bytesRead = await stream.ReadAsync(authResponse, 0, 2, token);
            if (bytesRead != 2 || authResponse[0] != 0x01 || authResponse[1] != 0x00)
            {
                return false;
            }

            return true;
        }

        public override async Task<bool> Validate(NetworkStream stream, CancellationToken token)
        {
            try
            {
                var versionBuffer = new byte[1];
                int bytesRead = await stream.ReadAsync(versionBuffer, 0, 1, token);
                if (bytesRead != 1 || versionBuffer[0] != 0x01) return false;

                var encodedBufferLength = new byte[1];
                bytesRead = await stream.ReadAsync(encodedBufferLength, 0, 1, token);
                if (bytesRead != 1) return false;

                int encodedLength = encodedBufferLength[0];
                var encodedBuffer = new byte[encodedLength];
                bytesRead = await stream.ReadAsync(encodedBuffer, 0, encodedLength, token);
                if (bytesRead != encodedLength) return false;

                var decodedBytes = AesGcmEncryption.DecodeBytes(encodedBuffer, _key);

                var utcBuffer = new byte[8];
                var keyPhraseBuffer = new byte[decodedBytes.Length - 8];
                Buffer.BlockCopy(decodedBytes, 0, utcBuffer, 0, 8);
                Buffer.BlockCopy(decodedBytes, 8, keyPhraseBuffer, 0, decodedBytes.Length - 8);

                var keyPhrase = Encoding.UTF8.GetString(keyPhraseBuffer);
                
                long clientUnixTimeMs = BitConverter.ToInt64(utcBuffer);
                long unixTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                /*
                +----+--------+
                |VER | STATUS |
                +----+--------+
                | 1  |   1    |
                +----+--------+
                */

                if (unixTimeMs - clientUnixTimeMs < _expiredTimeMs && keyPhrase == _keyPhrase)
                {
                    await stream.WriteAsync([0x01, 0x00], 0, 2, token); // Success
                    return true;
                }

                await stream.WriteAsync([0x01, 0x01], 0, 2, token); // Failure
                return false;
            }
            catch
            {
                return false;
            }
        }

        public override EncryptionBase GetEncryption()
        {
            return new AesGcmEncryption(_key);
        }
    }
}
