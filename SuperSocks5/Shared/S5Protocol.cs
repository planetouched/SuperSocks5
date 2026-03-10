using System.Net;
using System.Net.Sockets;
using System.Text;
using SuperSocks5.Shared.Encryption;
using SuperSocks5.Shared.Encryption._Base;
using SuperSocks5.Shared.Encryption.Xor;

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
        if (aTyp == S5Const.DomainName && packet.Command == S5Const.CmdConnect)
        {
            var lengthBuffer = new byte[1];
            await stream.ReadExactlyAsync(lengthBuffer, 0, 1, token);
            var domainBuffer = new byte[lengthBuffer[0]];
            await stream.ReadExactlyAsync(domainBuffer, 0, domainBuffer.Length, token);
            packet.TargetHost = Encoding.ASCII.GetString(domainBuffer);
        }
        else if (aTyp == S5Const.IPv4)
        {
            var ipBuffer = new byte[4];
            await stream.ReadExactlyAsync(ipBuffer, 0, 4, token);

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
            await stream.ReadExactlyAsync(ipBuffer, 0, 16, token);
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
        await stream.ReadExactlyAsync(portBuffer, 0, 2, token);

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
        await decodedStream.ReadExactlyAsync(header, 0, 4, token);

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

    public static async Task<(bool success, EncryptionBase? encryption)> ResponseHandshakeAsync(NetworkStream stream, IList<AuthCredentialsBase> responseAuths, CancellationToken token)
    {
        /*
        +----+----------+----------+
        | VER | NMETHODS | METHODS |
        +----+----------+----------+
        | 1  | 1        | 1 to 255 |
        +----+----------+----------+
         */

        Stream readStream = stream;

        var authHeader = new byte[2];
        await readStream.ReadExactlyAsync(authHeader, 0, authHeader.Length, token);

        var handshakeEncryption = HandshakeEncryptionFactory.Detect(authHeader[0]);

        var decodeResult = await handshakeEncryption.DecodeAuthRequest(stream, token);
        readStream = decodeResult.newStream;
        
        if (decodeResult.newHeader != null)
        {
            authHeader = decodeResult.newHeader;
        }

        if (authHeader[0] != S5Const.Version)
        {
            Console.WriteLine($"Socks version error: {authHeader[0]}");
            return (false, null);
        }

        int methodCount = authHeader[1];
        var methods = new byte[methodCount];
        await readStream.ReadExactlyAsync(methods, 0, methodCount, token);

        if (readStream != stream)
        {
            await readStream.DisposeAsync();
        }

        byte authMethod = S5Const.AuthNoAcceptableMethods;

        //optional: select the most suitable auth method

        AuthCredentialsBase selectedAuth = null;

        for (int r = methods.Length - 1; r >= 0; r--)
        {
            var authType = methods[r];
            for (int i = responseAuths.Count - 1; i >= 0; i--)
            {
                if (authType == responseAuths[i].AuthType)
                {
                    selectedAuth = responseAuths[i];
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

        var response = new [] { S5Const.Version, authMethod };
        var encodedResponse = await handshakeEncryption.EncodeAuthResponse(response, token);
        await stream.WriteAsync(encodedResponse, 0, encodedResponse.Length, token);

        if (selectedAuth == null)
        {
            Console.WriteLine("No auth method selected");
            return (false, null);
        }

        return (await selectedAuth.Validate(stream, token), selectedAuth.GetEncryption());
    }

    public static async Task<(bool success, EncryptionBase? encryption)> SendHandshakeAsync(NetworkStream stream, IList<AuthCredentialsBase> requestAuths, HandshakeEncryptionBase handshakeEncryption, CancellationToken token)
    {
        /*
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
        */

        var handshakeRequest = new byte[2 + requestAuths.Count];
        handshakeRequest[0] = S5Const.Version;
        handshakeRequest[1] = (byte)requestAuths.Count;

        for (int i = 0; i < requestAuths.Count; i++)
        {
            handshakeRequest[2 + i] = requestAuths[i].AuthType;
        }

        var handshakeEncRequest = await handshakeEncryption.EncodeAuthRequest(handshakeRequest, token);
        await stream.WriteAsync(handshakeEncRequest, 0, handshakeEncRequest.Length, token);

        /*
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
        */

        var handshakeResponse = await handshakeEncryption.DecodeAuthResponse(stream, token);

        if (handshakeResponse[0] != S5Const.Version)
        {
            Console.WriteLine($"Invalid socks version: {handshakeResponse[0]}");
            return (false, null);
        }

        AuthCredentialsBase? creds = null;

        foreach (var method in requestAuths)
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

    public static byte[] WrapUdpDatagram(S5Packet endPoint, byte[] payload)
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

            if (aTyp == S5Const.IPv4)
            {
                var ipBuffer = new byte[4];
                await stream.ReadExactlyAsync(ipBuffer, 0, 4, token);

                packet.IpAddress = new IPAddress(ipBuffer);
            }
            else if (aTyp == S5Const.IPv6)
            {
                var ipBuffer = new byte[16];
                await stream.ReadExactlyAsync(ipBuffer, 0, 16, token);
                packet.IpAddress = new IPAddress(ipBuffer);
            }
            else if (aTyp == S5Const.DomainName)
            {
                var lengthBuffer = new byte[1];
                await stream.ReadExactlyAsync(lengthBuffer, 0, 1, token);

                var domainBuffer = new byte[lengthBuffer[0]];
                await stream.ReadExactlyAsync(domainBuffer, 0, domainBuffer.Length, token);

                packet.TargetHost = Encoding.ASCII.GetString(domainBuffer);
            }

            // Читаем порт
            var portBuffer = new byte[2];
            await stream.ReadExactlyAsync(portBuffer, 0, 2, token);

            packet.TargetPort = (portBuffer[0] << 8) + portBuffer[1];

            payload = await BufferUtil.ReadToEnd(stream, token, 128);
        }

        packet.Payload = payload;
        return packet;
    }
}