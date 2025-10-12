using System.Net;
using System.Net.Sockets;
using SuperSocks5.Shared;
using SuperSocks5.Shared.Encryption._Base;
using SuperSocks5.Shared.Settings;

namespace SuperSocks5.Client;

public class S5Client : IDisposable
{
    private readonly EncryptionBase _encryption;

    public CancellationTokenSource Cts { get; }
    private readonly CancellationToken _token;

    private readonly TcpClient _tcpClient;
    private UdpClient? _udpClient;

    private bool _disposed;

    public S5Client(TcpClient tcpClient, EncryptionBase encryption, CancellationTokenSource cts)
    {
        Cts = cts;
        _token = Cts.Token;
        _tcpClient = tcpClient;
        _encryption = encryption;
    }

    public async Task<S5Packet> ConnectTcpAsync(S5Packet endPoint)
    {
        if (endPoint.Command == 0)
        {
            endPoint.Command = S5Const.CmdConnect;
        }

        var result = await S5Protocol.SendRequestAsync(_tcpClient.GetStream(), _encryption, endPoint, _token);

        if (result.Error != S5Const.NoError)
        {
            throw new Exception($"Socks5 server error: {result.Error}");
        }

        return result;
    }

    public async Task ConnectUdpAsync()
    {
        S5Packet udpRequest = default;

        udpRequest.Command = S5Const.CmdUdpAssociate;
        udpRequest.IpAddress = IPAddress.Any;
        udpRequest.TargetPort = 0;

        var udpResponse = await ConnectTcpAsync(udpRequest);
        _udpClient = new UdpClient();

        if (!string.IsNullOrEmpty(udpResponse.TargetHost))
        {
            _udpClient.Connect(udpResponse.TargetHost, udpResponse.TargetPort);
        }
        else
        {
            _udpClient.Connect(udpResponse.GetEndPoint());
        }
    }

    public Stream GetEncodingStream()
    {
        if (_tcpClient == null)
        {
            throw new Exception("Not initialized");
        }

        return _encryption.GetEncodingStream(_tcpClient.GetStream());
    }

    public async Task SendDatagramAsync(byte[] data, S5Packet endPoint)
    {
        if (_udpClient == null)
        {
            throw new Exception("Not initialized");
        }

        var message = S5Protocol.WrapUdpDatagram(endPoint, data, _token);
        await _udpClient.SendAsync(_encryption.EncodeDatagram(message), _token);
    }

    public async Task<byte[]> ReceiveUdpAsync()
    {
        if (_udpClient == null)
        {
            throw new Exception("Not initialized");
        }

        var result = await _udpClient.ReceiveAsync(_token);
        return _encryption.DecodeDatagram(result.Buffer, _token);
    }

    #region Request-Response

    public static async Task<byte[]> SendRequestTcpAsync(IList<AuthCredentialsBase> requestAuths, IPEndPoint proxy, S5Packet endPoint, byte[] data, CancellationTokenSource? cts = null)
    {
        using (var client = await S5ClientFactory.CreateAsync(requestAuths, proxy, cts))
        {
            await client.ConnectTcpAsync(endPoint);
            var stream = client.GetEncodingStream();
            await stream.WriteAsync(data, 0, data.Length, client._token);
            var result = await BufferUtil.ReadToEnd(stream, client._token);
            return result;
        }
    }

    public static async Task<byte[]> SendRequestUdpAsync(IList<AuthCredentialsBase> requestAuths, IPEndPoint proxy, S5Packet endPoint, byte[] data, CancellationTokenSource? cts = null)
    {
        using (var client = await S5ClientFactory.CreateAsync(requestAuths, proxy, cts))
        {
            await client.ConnectUdpAsync();
            await client.SendDatagramAsync(data, endPoint);
            var result = await client.ReceiveUdpAsync();
            return result;
        }
    }

    #endregion Request-Response

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        
        _tcpClient.Dispose();
        _udpClient?.Dispose();
        Cts.Cancel();
        Cts.Dispose();
    }
}