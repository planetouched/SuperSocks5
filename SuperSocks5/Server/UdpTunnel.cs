using System.Net;
using SuperSocks5.Shared;
using System.Net.Sockets;
using SuperSocks5.Shared.Encryption._Base;

namespace SuperSocks5.Server;

public class UdpTunnel : IDisposable
{
    private readonly UdpClient _udpUpstream;
    private readonly UdpClient _udpClient;

    private readonly bool _proxy;
    private readonly EncryptionBase _nextEncryption;
    private readonly EncryptionBase _prevEncryption;

    private bool _disposed;

    public int Port => ((IPEndPoint)_udpClient.Client.LocalEndPoint).Port;

    private readonly CancellationTokenSource _cts;

    public UdpTunnel(IPEndPoint? proxyEndPoint, EncryptionBase prevEncryption, EncryptionBase nextEncryption)
    {
        _cts = new CancellationTokenSource();

        _prevEncryption = prevEncryption;
        _nextEncryption = nextEncryption;
        _udpClient = new UdpClient(0);
        _udpUpstream = new UdpClient();

        if (proxyEndPoint != null)
        {
            //если впереди proxy то сразу коннектимся к его сокету
            _udpUpstream.Connect(proxyEndPoint);
            _proxy = true;
        }

        var token = _cts.Token;

        _ = Task.Run(() => ReceiveClientTask(token), token);
    }

    private async Task ReceiveClientTask(CancellationToken token)
    {
        try
        {
            bool clientConnected = false;
            bool upstreamConnected = false;

            while (true)
            {
                var udpResult = await _udpClient.ReceiveAsync(token);

                if (!clientConnected)
                {
                    //коннектимся к клиенту иначе не сможем отправлять обратно сообщения
                    _udpClient.Connect(udpResult.RemoteEndPoint);
                    clientConnected = true;
                }

                if (_proxy)
                {
                    if (!upstreamConnected)
                    {
                        upstreamConnected = true;
                        _ = Task.Run(() => ReceiveUpstreamTask(token), token);
                    }

                    await _udpUpstream.SendAsync(
                        _nextEncryption.EncodeDatagram(
                            _prevEncryption.DecodeDatagram(udpResult.Buffer, token)), token);
                }
                else
                {
                    var udpMessage = await S5Protocol.UnwrapUdpDatagramAsync(_prevEncryption.DecodeDatagram(udpResult.Buffer, token), token);

                    if (udpMessage.FrameNum != 0) //no FRAG support
                    {
                        continue;
                    }
                        
                    if (!upstreamConnected)
                    {
                        if (!string.IsNullOrEmpty(udpMessage.TargetHost))
                        {
                            _udpUpstream.Connect(udpMessage.TargetHost, udpMessage.TargetPort);
                        }
                        else
                        {
                            _udpUpstream.Connect(udpMessage.GetEndPoint());
                        }

                        upstreamConnected = true;
                        _ = Task.Run(() => ReceiveUpstreamTask(token), token);
                    }

                    //тут нет шифрования
                    await _udpUpstream.SendAsync(udpMessage.Payload, token);
                }
            }
        }
        catch (Exception)
        {
            // ignored
        }
    }

    private async Task ReceiveUpstreamTask(CancellationToken token)
    {
        try
        {
            while (true)
            {
                var udpResult = await _udpUpstream.ReceiveAsync(token);

                await _udpClient.SendAsync(
                    _prevEncryption.EncodeDatagram(
                        _nextEncryption.DecodeDatagram(udpResult.Buffer, token)), token);
            }
        }
        catch (Exception)
        {
            // ignored
        }
    }

    public void Dispose()
    {
        if (_disposed) return;

        _cts.Cancel();
        _udpUpstream.Dispose();
        _udpClient.Dispose();
        _disposed = true;
    }
}