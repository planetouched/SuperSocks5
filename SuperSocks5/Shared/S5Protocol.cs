using System.Net;
using System.Net.Sockets;
using System.Text;
using SuperSocks5.Shared.Encryption._Base;
using SuperSocks5.Shared.Settings;

namespace SuperSocks5.Shared;

public static class S5Protocol
{
    public static async Task SendOpResultAsync(NetworkStream stream, EncryptionBase encryption, byte errorCode, IPAddress ipAddress, int port, CancellationToken token)
    {
        /*
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        */

        byte ipType = ipAddress.AddressFamily == AddressFamily.InterNetwork ? S5Const.IPv4 : S5Const.IPv6;

        var response = new List<byte> { S5Const.Version, errorCode, 0x00, ipType };
        response.AddRange(ipAddress.GetAddressBytes());

        response.Add((byte)(port >> 8));
        response.Add((byte)port);

        var encodedResult = await encryption.EncodeResult(response.ToArray());
        await stream.WriteAsync(encodedResult, 0, encodedResult.Length, token);
    }


    private static async Task<S5Packet> ResponseRequestInnerAsync(byte aTyp, S5Packet packet, Stream stream, CancellationToken token)
    {
        int bytesRead;

        if (aTyp == S5Const.DomainName && packet.Command == S5Const.CmdConnect)
        {
            var lengthBuffer = new byte[1];
            bytesRead = await stream.ReadAsync(lengthBuffer, 0, 1, token);
            if (bytesRead != 1)
            {
                packet.Error = S5Const.ErrorConnectionRefused;
                return packet;
            }

            var domainBuffer = new byte[lengthBuffer[0]];
            bytesRead = await stream.ReadAsync(domainBuffer, 0, domainBuffer.Length, token);
            if (bytesRead != domainBuffer.Length)
            {
                packet.Error = S5Const.ErrorConnectionRefused;
                return packet;
            }

            packet.TargetHost = Encoding.ASCII.GetString(domainBuffer);
        }
        else if (aTyp == S5Const.IPv4)
        {
            var ipBuffer = new byte[4];
            bytesRead = await stream.ReadAsync(ipBuffer, 0, 4, token);
            if (bytesRead != 4)
            {
                packet.Error = S5Const.ErrorConnectionRefused;
                return packet;
            }

            packet.IpAddress = new IPAddress(ipBuffer);

            if (packet.Command == S5Const.CmdUdpAssociate && !packet.IpAddress.Equals(IPAddress.Any))
            {
                packet.Error = S5Const.ErrorAddressTypeNotSupported;
                return packet;
            }
        }
        else if (aTyp == S5Const.IPv6)
        {
            var ipBuffer = new byte[16];
            bytesRead = await stream.ReadAsync(ipBuffer, 0, 16, token);
            if (bytesRead != 16)
            {
                packet.Error = S5Const.ErrorConnectionRefused;
                return packet;
            }

            packet.IpAddress = new IPAddress(ipBuffer);

            if (packet.Command == S5Const.CmdUdpAssociate && !packet.IpAddress.Equals(IPAddress.IPv6Any))
            {
                packet.Error = S5Const.ErrorAddressTypeNotSupported;
                return packet;
            }
        }
        else
        {
            packet.Error = S5Const.ErrorAddressTypeNotSupported;
            return packet;
        }

        // Читаем порт
        var portBuffer = new byte[2];
        bytesRead = await stream.ReadAsync(portBuffer, 0, 2, token);
        if (bytesRead != 2)
        {
            packet.Error = S5Const.ErrorConnectionRefused;
            return packet;
        }

        packet.TargetPort = (portBuffer[0] << 8) + portBuffer[1];
        if (packet.Command == S5Const.CmdUdpAssociate && packet.TargetPort != 0)
        {
            packet.Error = S5Const.ErrorAddressTypeNotSupported;
            return packet;
        }

        return packet;
    }


    public static async Task<S5Packet> ResponseRequestAsync(NetworkStream stream, EncryptionBase encryption, CancellationToken token)
    {
        /*
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        */

        S5Packet packet = default;

        var decodedStream = await encryption.DecodeHeader(stream, token);

        var header = new byte[4];
        int bytesRead = await decodedStream.ReadAsync(header, 0, 4, token);

        if (bytesRead != 4)
        {
            packet.Error = S5Const.ErrorConnectionRefused;
            return packet;
        }

        if (header[0] != S5Const.Version)
        {
            packet.Error = S5Const.ErrorConnectionRefused;
            return packet;
        }

        packet.Command = header[1];

        if (packet.Command == S5Const.CmdConnect || packet.Command == S5Const.CmdUdpAssociate)
        {
            return await ResponseRequestInnerAsync(header[3], packet, decodedStream, token);
        }

        packet.Error = S5Const.ErrorCommandNotSupported;

        if (decodedStream != stream)
        {
            await decodedStream.DisposeAsync();
        }

        return packet;
    }

    public static async Task<S5Packet> SendRequestAsync(NetworkStream stream, EncryptionBase encryption, S5Packet packet, CancellationToken token)
    {
        S5Packet backPacket = default;

        /*
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        */

        var header = new List<byte> { S5Const.Version, packet.Command, 0x00 };

        if (!string.IsNullOrEmpty(packet.TargetHost))
        {
            header.Add(S5Const.DomainName);
            var bytes = Encoding.ASCII.GetBytes(packet.TargetHost);
            header.Add((byte)bytes.Length);
            header.AddRange(bytes);
        }
        else
        {
            if (packet.IpAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                header.Add(S5Const.IPv4);
            }
            else
            {
                header.Add(S5Const.IPv6);
            }

            header.AddRange(packet.IpAddress.GetAddressBytes());
        }

        header.Add((byte)(packet.TargetPort >> 8));
        header.Add((byte)packet.TargetPort);

        var encodedHeader = await encryption.EncodeHeader(header.ToArray());
        await stream.WriteAsync(encodedHeader, 0, encodedHeader.Length, token);


        //SendResultAsync

        /*
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        */

        var decodedStream = await encryption.DecodeResult(stream, token);

        var response = new byte[255];
        var bytesRead = await decodedStream.ReadAsync(response, 0, 255, token);
        if (bytesRead < 2)
        {
            backPacket.Error = S5Const.ErrorGeneralSocksServerFailure;
            return backPacket;
        }

        if (response[0] != S5Const.Version)
        {
            backPacket.Error = S5Const.ErrorConnectionRefused;
            return backPacket;
        }

        //распарсим 
        var aTyp = response[3];
        if (aTyp == S5Const.IPv4)
        {
            var ip4Buffer = new byte[4];
            Buffer.BlockCopy(response, 4, ip4Buffer, 0, ip4Buffer.Length);
            backPacket.IpAddress = new IPAddress(ip4Buffer);

            var portBuffer = new byte[2];
            Buffer.BlockCopy(response, 4 + ip4Buffer.Length, portBuffer, 0, portBuffer.Length);
            backPacket.TargetPort = (portBuffer[0] << 8) + portBuffer[1];
        }
        else if (aTyp == S5Const.IPv6)
        {
            var ip6Buffer = new byte[16];
            Buffer.BlockCopy(response, 4, ip6Buffer, 0, ip6Buffer.Length);

            var portBuffer = new byte[2];
            Buffer.BlockCopy(response, 4 + ip6Buffer.Length, portBuffer, 0, portBuffer.Length);
            backPacket.TargetPort = (portBuffer[0] << 8) + portBuffer[1];
        }

        if (decodedStream != stream)
        {
            await decodedStream.DisposeAsync();
        }

        return backPacket;
    }

    public static async Task<(bool success, EncryptionBase? encryption)> ResponseHandshakeAsync(NetworkStream stream, S5Settings settings, CancellationToken token)
    {
        /*
        +----+----------+----------+
        | VER | NMETHODS | METHODS |
        +----+----------+----------+
        | 1  | 1        | 1 to 255 |
        +----+----------+----------+
         */

        var authBuffer = new byte[2];
        int bytesRead = await stream.ReadAsync(authBuffer, 0, 2, token);

        if (bytesRead != 2)
        {
            //Console.WriteLine($"Failed to select an authentication method, the client sent {bytesRead} bytes.");
            return (false, null);
        }

        if (authBuffer[0] != S5Const.Version)
        {
            Console.WriteLine($"Socks version error: {authBuffer[0]}");
            return (false, null);
        }

        int methodCount = authBuffer[1];
        var methods = new byte[methodCount];
        bytesRead = await stream.ReadAsync(methods, 0, methodCount, token);

        if (bytesRead != methodCount)
        {
            Console.WriteLine("Auth methods count mismatch");
            return (false, null);
        }

        byte authMethod = S5Const.AuthNoAcceptableMethods;

        //optional: select the most suitable auth method

        AuthCredentialsBase selectedAuth = null;

        for (int r = methods.Length - 1; r >= 0; r--)
        {
            var authType = methods[r];
            for (int i = settings.ResponseAuths.Count - 1; i >= 0; i--)
            {
                if (authType == settings.ResponseAuths[i].AuthType)
                {
                    selectedAuth = settings.ResponseAuths[i];
                    authMethod = authType;
                    break;
                }
            }

            if (selectedAuth != null) break;
        }

        /*
        +-----+--------+
        | VER | METHOD |
        +-----+--------+
        | 1   | 1      |
        +-----+--------+
        */

        await stream.WriteAsync([S5Const.Version, authMethod], 0, 2, token);

        // if (authMethod == S5Const.AuthNoAcceptableMethods)
        // {
        //     Console.WriteLine("No auth method selected");
        //     return (false, null);
        // }

        if (selectedAuth == null)
        {
            Console.WriteLine("No auth method selected");
            return (false, null);
        }

        return (await selectedAuth.Validate(stream, token), selectedAuth.GetEncryption());
    }

    public static async Task<(bool success, EncryptionBase? encryption)> SendHandshakeAsync(NetworkStream stream, S5Settings settings, CancellationToken token)
    {
        /*
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
        */

        var handshake = new byte[2 + settings.RequestAuths.Count];
        handshake[0] = S5Const.Version;
        handshake[1] = (byte)settings.RequestAuths.Count;

        for (int i = 0; i < settings.RequestAuths.Count; i++)
        {
            handshake[2 + i] = settings.RequestAuths[i].AuthType;
        }

        await stream.WriteAsync(handshake, 0, handshake.Length, token);

        /*
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        */

        var handshakeResponse = new byte[2];
        int bytesRead = await stream.ReadAsync(handshakeResponse, 0, 2, token);

        if (bytesRead != 2)
        {
            return (false, null);
        }

        if (handshakeResponse[0] != S5Const.Version)
        {
            Console.WriteLine($"Invalid socks version: {handshakeResponse[0]}");
            return (false, null);
        }

        AuthCredentialsBase? creds = null;

        foreach (var method in settings.RequestAuths)
        {
            if (method.AuthType == handshakeResponse[1])
            {
                creds = method;
                var result = await method.Authenticate(stream, token);
                if (!result)
                {
                    Console.WriteLine("Auth failed");
                    return (false, null);
                }

                break;
            }
        }

        if (creds == null)
        {
            Console.WriteLine("Auth failed");
            return (false, null);
        }

        return (true, creds.GetEncryption());
    }

    public static byte[] WrapUdpDatagram(S5Packet endPoint, byte[] payload, CancellationToken token)
    {
        /*
        +----+------+------+----------+----------+----------+
        |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        +----+------+------+----------+----------+----------+
        | 2  |  1   |  1   | Variable |    2     | Variable |
        +----+------+------+----------+----------+----------+
        */

        List<byte> message = new(payload.Length + 50)
        {
            0x00, 0x00, endPoint.FrameNum
        };

        if (!string.IsNullOrEmpty(endPoint.TargetHost))
        {
            message.Add(S5Const.DomainName);
            var bytes = Encoding.ASCII.GetBytes(endPoint.TargetHost);
            message.Add((byte)bytes.Length);
            message.AddRange(bytes);
        }
        else if (endPoint.IpAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            message.Add(S5Const.IPv4);
            message.AddRange(endPoint.IpAddress.GetAddressBytes());
        }
        else if (endPoint.IpAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            message.Add(S5Const.IPv6);
            message.AddRange(endPoint.IpAddress.GetAddressBytes());
        }

        message.Add((byte)(endPoint.TargetPort >> 8));
        message.Add((byte)endPoint.TargetPort);

        message.AddRange(payload);

        return message.ToArray();
    }

    public static async Task<S5Packet> UnwrapUdpDatagramAsync(byte[] data, CancellationToken token)
    {
        S5Packet packet = default;

        /*
        +----+------+------+----------+----------+----------+
        |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        +----+------+------+----------+----------+----------+
        | 2  |  1   |  1   | Variable |    2     | Variable |
        +----+------+------+----------+----------+----------+
        */

        if (data.Length < 10 || data[0] != 0 || data[1] != 0)
        {
            return packet;
        }

        packet.FrameNum = data[2];

        var aTyp = data[3];
        byte[]? payload;

        using (var stream = new MemoryStream(data))
        {
            stream.Position = 4;

            int bytesRead;

            if (aTyp == S5Const.IPv4)
            {
                var ipBuffer = new byte[4];
                bytesRead = await stream.ReadAsync(ipBuffer, 0, 4, token);
                if (bytesRead != 4)
                {
                    return packet;
                }

                packet.IpAddress = new IPAddress(ipBuffer);
            }
            else if (aTyp == S5Const.IPv6)
            {
                var ipBuffer = new byte[16];
                bytesRead = await stream.ReadAsync(ipBuffer, 0, 16, token);
                if (bytesRead != 4)
                {
                    return packet;
                }

                packet.IpAddress = new IPAddress(ipBuffer);
            }
            else if (aTyp == S5Const.DomainName)
            {
                var lengthBuffer = new byte[1];
                bytesRead = await stream.ReadAsync(lengthBuffer, 0, 1, token);
                if (bytesRead != 1)
                {
                    return packet;
                }

                var domainBuffer = new byte[lengthBuffer[0]];
                bytesRead = await stream.ReadAsync(domainBuffer, 0, domainBuffer.Length, token);
                if (bytesRead != domainBuffer.Length)
                {
                    return packet;
                }

                packet.TargetHost = Encoding.ASCII.GetString(domainBuffer);
            }

            // Читаем порт
            var portBuffer = new byte[2];
            bytesRead = await stream.ReadAsync(portBuffer, 0, 2, token);
            if (bytesRead != 2)
            {
                return packet;
            }

            packet.TargetPort = (portBuffer[0] << 8) + portBuffer[1];

            payload = await BufferUtil.ReadToEnd(stream, token, 128);
        }

        packet.Payload = payload;
        return packet;
    }
}