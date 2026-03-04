using System.Net.Sockets;
using System.Text;
using SuperSocks5.Shared.Encryption._Base;

namespace SuperSocks5.Shared.Encryption.AESGcm
{
    public class AesGcmUserPassCredentials : AuthCredentialsBase
    {
        public string Username { get; }
        public string Password { get; }
        private readonly byte[] _key;

        public AesGcmUserPassCredentials(string username, string password, byte[] key) : base(0x83)
        {
            Username = username;
            Password = password;
            _key = key;
        }

        public override async Task<bool> Authenticate(NetworkStream stream, CancellationToken token)
        {
            /*
            +----+------+----------+------+----------+
            |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            +----+------+----------+------+----------+
            | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            +----+------+----------+------+----------+
            */

            var usernameBytes = Encoding.UTF8.GetBytes(Username);
            var passwordBytes = Encoding.UTF8.GetBytes(Password);
            var request = new List<byte>(3 + usernameBytes.Length + passwordBytes.Length);

            request.Add(0x01);

            request.Add((byte)usernameBytes.Length);
            request.AddRange(usernameBytes);
            request.Add((byte)passwordBytes.Length);
            request.AddRange(passwordBytes);

            //шифруем
            var encryptedRequest = await AesGcmEncryption.EncodeMessageWithLength(request.ToArray(), _key);
            await stream.WriteAsync(encryptedRequest, 0, encryptedRequest.Length, token);

            /*
            +----+--------+
            |VER | STATUS |
            +----+--------+
            | 1  |   1    |
            +----+--------+
            */

            //дешифруем ответ
            await using var responseStream = await AesGcmEncryption.DecodeMessageWithLength(stream, _key, token);

            var response = new byte[2];
            await responseStream.ReadExactlyAsync(response, 0, response.Length, token);

            if (response[0] != 0x01 || response[1] != 0x00)
            {
                return false;
            }

            return true;
        }

        public override async Task<bool> Validate(NetworkStream stream, CancellationToken token)
        {
            /*
             +-----+------+----------+------+----------+
             | VER | ULEN | UNAME    | PLEN | PASSWD   |
             +----+-------+----------+------+----------+
             | 1  | 1     | 1 to 255 | 1    | 1 to 255 |
             +----+-------+----------+------+----------+
             */

            try
            {
                //дешифруем
                await using var requestStream = await AesGcmEncryption.DecodeMessageWithLength(stream, _key, token);
                
                // Читаем версию аутентификации
                var versionBuffer = new byte[1];
                await requestStream.ReadExactlyAsync(versionBuffer, 0, 1, token);
                if (versionBuffer[0] != 0x01) return false;

                // Читаем длину username
                var usernameLengthBuffer = new byte[1];
                await requestStream.ReadExactlyAsync(usernameLengthBuffer, 0, 1, token);

                int usernameLength = usernameLengthBuffer[0];

                // Читаем username
                var usernameBuffer = new byte[usernameLength];
                await requestStream.ReadExactlyAsync(usernameBuffer, 0, usernameLength, token);

                var username = Encoding.UTF8.GetString(usernameBuffer);

                // Читаем длину password
                var passwordLengthBuffer = new byte[1];
                await requestStream.ReadExactlyAsync(passwordLengthBuffer, 0, 1, token);

                int passwordLength = passwordLengthBuffer[0];

                // Читаем password
                var passwordBuffer = new byte[passwordLength];
                await requestStream.ReadExactlyAsync(passwordBuffer, 0, passwordLength, token);

                var password = Encoding.UTF8.GetString(passwordBuffer);

                /*
                +----+--------+
                |VER | STATUS |
                +----+--------+
                | 1  |   1    |
                +----+--------+
                */

                //шифруем
                byte[] encryptedResponse;

                if (Username == username && Password == password)
                {
                    encryptedResponse = await AesGcmEncryption.EncodeMessageWithLength([0x01, 0x00], _key);

                    await stream.WriteAsync(encryptedResponse, 0, encryptedResponse.Length, token); // Success
                    return true;
                }

                encryptedResponse = await AesGcmEncryption.EncodeMessageWithLength([0x01, 0x01], _key);
                await stream.WriteAsync(encryptedResponse, 0, encryptedResponse.Length, token); // Failure
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
