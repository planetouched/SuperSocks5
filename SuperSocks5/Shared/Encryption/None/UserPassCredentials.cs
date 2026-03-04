using System.Net.Sockets;
using System.Text;
using SuperSocks5.Shared.Encryption._Base;

namespace SuperSocks5.Shared.Encryption.None;

public class UserPassCredentials : AuthCredentialsBase
{
    public string Username { get; }
    public string Password { get; }
    
    public UserPassCredentials(string username, string password) : base(AuthMethodType.UsernamePassword)
    {
        Username = username;
        Password = password;
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
        await stream.WriteAsync(request.ToArray(), 0, request.Count, token);

        /*
        +----+--------+
        |VER | STATUS |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        */
        
        var authResponse = new byte[2];

        await stream.ReadExactlyAsync(authResponse, 0, 2, token);
        if (authResponse[0] != 0x01 || authResponse[1] != 0x00)
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
            await stream.ReadExactlyAsync(versionBuffer, 0, 1, token);
            if (versionBuffer[0] != 0x01) return false;

            // Читаем длину username
            var usernameLengthBuffer = new byte[1];
            await stream.ReadExactlyAsync(usernameLengthBuffer, 0, 1, token);

            int usernameLength = usernameLengthBuffer[0];

            // Читаем username
            var usernameBuffer = new byte[usernameLength];
            await stream.ReadExactlyAsync(usernameBuffer, 0, usernameLength, token);

            var username = Encoding.UTF8.GetString(usernameBuffer);

            // Читаем длину password
            var passwordLengthBuffer = new byte[1];
            await stream.ReadExactlyAsync(passwordLengthBuffer, 0, 1, token);
            

            int passwordLength = passwordLengthBuffer[0];

            // Читаем password
            var passwordBuffer = new byte[passwordLength];
            await stream.ReadExactlyAsync(passwordBuffer, 0, passwordLength, token);

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
        return new NoEncryption();
    }
}