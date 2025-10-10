using SuperSocks5.Shared;
using System.Net;
using System.Net.Sockets;
using SuperSocks5.Shared.Encryption._Base;
using SuperSocks5.Shared.Encryption.None;
using SuperSocks5.Shared.Settings;

namespace SuperSocks5.Server;

public class S5Server
{
    private IPAddress _serverIpAddress;
    private readonly IPAddress _ipAddress;
    private readonly int _port;
    private readonly S5Settings _settings;

    public CancellationTokenSource Cts { get; } = new();
    public event Func<S5Packet, CancellationToken, Task<IPEndPoint>>? OnRedirect;

    public S5Server(IPAddress ipAddress, int port, S5Settings settings)
    {
        _ipAddress = ipAddress;
        _port = port;
        _settings = settings;
    }

    public async Task StartAsync()
    {
        var listener = new TcpListener(_ipAddress, _port);
        listener.Start();

        _serverIpAddress = Dns.GetHostAddresses(Dns.GetHostName()).FirstOrDefault(ip => ip.AddressFamily == _ipAddress.AddressFamily);

        Console.WriteLine($"Server started {listener.LocalEndpoint}");

        var token = Cts.Token;

        while (true)
        {
            if (token.IsCancellationRequested)
            {
                OnRedirect = null;
                Console.WriteLine("Server stopped");
                return;
            }

            try
            {
                var client = await listener.AcceptTcpClientAsync(token);
                _ = Task.Run(() => HandleClientAsync(client), token);
            }
            catch (OperationCanceledException)
            {
                OnRedirect = null;
                Console.WriteLine("Server stopped");
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Server error accepting client: {ex.Message}");
            }
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        var token = Cts.Token;

        if (client.Client.RemoteEndPoint == null)
        {
            return;
        }

        try
        {
            using (client)
            {
                var clientStream = client.GetStream();
                var pair = await S5Protocol.ResponseHandshakeAsync(clientStream, _settings, token);
                
                if (!pair.success)
                {
                    return;
                }

                var prevEncryption = pair.encryption;

                var packet = await S5Protocol.ResponseRequestAsync(clientStream, prevEncryption, token);

                var endPoint = packet.GetEndPoint();
                if (endPoint != null)
                {
                    Console.WriteLine($"-> {endPoint}, encryption: {prevEncryption.Name}");
                }
                else if (!string.IsNullOrEmpty(packet.TargetHost))
                {
                    Console.WriteLine($"-> {packet.TargetHost}:{packet.TargetPort}, encryption: {prevEncryption.Name}");
                }

                if (packet.Error != S5Const.NoError)
                {
                    await S5Protocol.SendOpResultAsync(clientStream, prevEncryption, packet.Error, _serverIpAddress, _port, token);
                    return;
                }

                if (OnRedirect != null)
                {
                    var upstreamEndPoint = await OnRedirect.Invoke(packet, token);

                    if (upstreamEndPoint != null)
                    {
                        if (packet.Command == S5Const.CmdConnect)
                        {
                            await ToSocks5Async(upstreamEndPoint, packet, clientStream, prevEncryption);
                        }
                        else if (packet.Command == S5Const.CmdUdpAssociate)
                        {
                            await ToSocks5UdpAsync(upstreamEndPoint, client, prevEncryption);
                        }
                    }
                    else
                    {
                        if (packet.Command == S5Const.CmdConnect)
                        {
                            await ToDirectAsync(packet, clientStream, prevEncryption);
                        }
                        else if (packet.Command == S5Const.CmdUdpAssociate)
                        {
                            await ToDirectUdpAsync(client, prevEncryption);
                        }
                    }
                }
                else
                {
                    if (_settings.UpstreamProxy != null)
                    {
                        if (packet.Command == S5Const.CmdConnect)
                        {
                            await ToSocks5Async(_settings.UpstreamProxy, packet, clientStream, prevEncryption);
                        }
                        else if (packet.Command == S5Const.CmdUdpAssociate)
                        {
                            await ToSocks5UdpAsync(_settings.UpstreamProxy, client, prevEncryption);
                        }
                    }
                    else
                    {
                        if (packet.Command == S5Const.CmdConnect)
                        {
                            await ToDirectAsync(packet, clientStream, prevEncryption);
                        }

                        else if (packet.Command == S5Const.CmdUdpAssociate)
                        {
                            await ToDirectUdpAsync(client, prevEncryption);
                        }
                    }
                }
            }
        }
        catch (Exception)
        {
            //await udpCancellationTokenSource.CancelAsync();
        }
    }

    #region UDP

    private async Task ToDirectUdpAsync(TcpClient client, EncryptionBase prevEncryption)
    {
        var clientStream = client.GetStream();
        var token = Cts.Token;

        using (var udpTunnel = new UdpTunnel(null, prevEncryption, new NoEncryption()))
        {
            await S5Protocol.SendOpResultAsync(clientStream, prevEncryption, 0, _serverIpAddress, udpTunnel.Port, token);
            Console.WriteLine($"Open UDP tunnel {_serverIpAddress}:{udpTunnel.Port}");

            //wait disconnect
            var checkBuffer = new byte[1];
            _ = await clientStream.ReadAsync(checkBuffer, 0, 1, token);
            Console.WriteLine($"Close UDP tunnel {_serverIpAddress}:{udpTunnel.Port}");
        }
    }

    public async Task ToSocks5UdpAsync(IPEndPoint upstreamEndPoint, TcpClient client, EncryptionBase prevEncryption)
    {
        var clientStream = client.GetStream();

        var token = Cts.Token;

        S5Packet udpPacket = default;

        udpPacket.Command = S5Const.CmdUdpAssociate;
        udpPacket.IpAddress = IPAddress.Any;
        udpPacket.TargetPort = 0;

        using (var upstreamClient = new TcpClient())
        {
            await upstreamClient.ConnectAsync(upstreamEndPoint, token);
            var upstreamStream = upstreamClient.GetStream();

            var pair = await S5Protocol.SendHandshakeAsync(upstreamStream, _settings, token);

            if (pair.success)
            {
                var nextEncryption = pair.encryption;

                var udpBackPacket = await S5Protocol.SendRequestAsync(upstreamStream, nextEncryption, udpPacket, token);
                using (var udpTunnel = new UdpTunnel(udpBackPacket.GetEndPoint(), prevEncryption, nextEncryption))
                {
                    await S5Protocol.SendOpResultAsync(clientStream, prevEncryption, 0, _serverIpAddress, udpTunnel.Port, token);
                    Console.WriteLine($"Open UDP tunnel {_serverIpAddress}:{udpTunnel.Port}");

                    //wait disconnect
                    var checkBuffer = new byte[1];
                    _ = await clientStream.ReadAsync(checkBuffer, 0, 1, token);
                    Console.WriteLine($"Close UDP tunnel {_serverIpAddress}:{udpTunnel.Port}");
                }
            }
        }
    }

    #endregion UDP

    #region TCP

    public async Task ToSocks5Async(IPEndPoint upstreamEndPoint, S5Packet packet, NetworkStream clientStream, EncryptionBase prevEncryption)
    {
        var token = Cts.Token;

        using (var upstreamClient = new TcpClient())
        {
            await upstreamClient.ConnectAsync(upstreamEndPoint, token);
            var upstreamStream = upstreamClient.GetStream();

            var pair = await S5Protocol.SendHandshakeAsync(upstreamStream, _settings, token);
            if (pair.success)
            {
                var nextEncryption = pair.encryption;

                var backPacket = await S5Protocol.SendRequestAsync(upstreamStream, nextEncryption, packet, token);
                await S5Protocol.SendOpResultAsync(clientStream, prevEncryption, backPacket.Error, _serverIpAddress, _port, token);
                if (backPacket.Error == S5Const.NoError)
                {
                    await TunnelDataBetweenStreams(prevEncryption, nextEncryption, clientStream, upstreamStream, token);
                }
            }
        }
    }

    public async Task ToDirectAsync(S5Packet packet, NetworkStream clientStream, EncryptionBase prevEncryption)
    {
        var token = Cts.Token;

        using (var targetEndPoint = new TcpClient())
        {
            try
            {
                if (!string.IsNullOrEmpty(packet.TargetHost))
                {
                    await targetEndPoint.ConnectAsync(packet.TargetHost, packet.TargetPort, token);
                }
                else
                {
                    await targetEndPoint.ConnectAsync(packet.IpAddress, packet.TargetPort, token);
                }

                await S5Protocol.SendOpResultAsync(clientStream, prevEncryption, S5Const.NoError, _serverIpAddress, _port, token);
            }
            catch (Exception)
            {
                await S5Protocol.SendOpResultAsync(clientStream, prevEncryption, S5Const.ErrorHostUnreachable, _ipAddress, _port, token);
                return;
            }

            var upstreamStream = targetEndPoint.GetStream();
            await TunnelDataBetweenStreams(prevEncryption, new NoEncryption(), clientStream, upstreamStream, token);
        }
    }

    public async Task TunnelDataBetweenStreams(
        EncryptionBase prevEncryption, 
        EncryptionBase nextEncryption, 
        NetworkStream clientStream, 
        NetworkStream upstreamStream, 
        CancellationToken token)
    {

        var clientDecodingStream = prevEncryption.GetDecodingStream(clientStream);
        var upstreamEncodingStream = nextEncryption.GetEncodingStream(upstreamStream);

        var upstreamDecodingStream = nextEncryption.GetDecodingStream(upstreamStream);
        var clientEncodingStream = prevEncryption.GetEncodingStream(clientStream);

        await Task.WhenAny(
            TunnelDataAsync(clientDecodingStream, upstreamEncodingStream, token),
            TunnelDataAsync(upstreamDecodingStream, clientEncodingStream, token)
        );

        if (clientDecodingStream != clientStream)
        {
            clientDecodingStream.Dispose();
        }
        
        if (clientEncodingStream != clientStream)
        {
            clientEncodingStream.Dispose();
        }

        if (upstreamDecodingStream != upstreamStream)
        {
            upstreamDecodingStream.Dispose();
        }

        if (upstreamEncodingStream != upstreamStream)
        {
            upstreamEncodingStream.Dispose();
        }
    }

    protected async Task TunnelDataAsync(Stream source, Stream destination, CancellationToken token)
    {
        var buffer = new byte[4096];

        try
        {
            while (true)
            {
                int bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, token);
                if (bytesRead == 0) break;

                await destination.WriteAsync(buffer, 0, bytesRead, token);
            }
        }
        catch (Exception)
        {
            // Туннелирование прервано, это нормально при закрытии соединения
        }
    }

    #endregion TCP
}