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
            var message = new List<byte>(3 + usernameBytes.Length + passwordBytes.Length);

            message.Add(0x01);

            message.Add((byte)usernameBytes.Length);
            message.AddRange(usernameBytes);
            message.Add((byte)passwordBytes.Length);
            message.AddRange(passwordBytes);
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
            /*
             +-----+------+----------+------+----------+
             | VER | ULEN | UNAME    | PLEN | PASSWD   |
             +----+-------+----------+------+----------+
             | 1  | 1     | 1 to 255 | 1    | 1 to 255 |
             +----+-------+----------+------+----------+
             */

            try
            {
                // Читаем версию аутентификации
                var versionBuffer = new byte[1];
                int bytesRead = await stream.ReadAsync(versionBuffer, 0, 1, token);
                if (bytesRead != 1 || versionBuffer[0] != 0x01) return false;

                // Читаем длину username
                var usernameLengthBuffer = new byte[1];
                bytesRead = await stream.ReadAsync(usernameLengthBuffer, 0, 1, token);
                if (bytesRead != 1) return false;

                int usernameLength = usernameLengthBuffer[0];

                // Читаем username
                var usernameBuffer = new byte[usernameLength];
                bytesRead = await stream.ReadAsync(usernameBuffer, 0, usernameLength, token);
                if (bytesRead != usernameLength) return false;

                var username = Encoding.UTF8.GetString(usernameBuffer);

                // Читаем длину password
                var passwordLengthBuffer = new byte[1];
                bytesRead = await stream.ReadAsync(passwordLengthBuffer, 0, 1, token);
                if (bytesRead != 1) return false;

                int passwordLength = passwordLengthBuffer[0];

                // Читаем password
                var passwordBuffer = new byte[passwordLength];
                bytesRead = await stream.ReadAsync(passwordBuffer, 0, passwordLength, token);
                if (bytesRead != passwordLength) return false;

                var password = Encoding.UTF8.GetString(passwordBuffer);

                /*
                +----+--------+
                |VER | STATUS |
                +----+--------+
                | 1  |   1    |
                +----+--------+
                */

                if (Username == username && Password == password)
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
