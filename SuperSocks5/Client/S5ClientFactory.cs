using SuperSocks5.Shared;
using SuperSocks5.Shared.Settings;
using System.Net;
using System.Net.Sockets;

namespace SuperSocks5.Client
{
    public static class S5ClientFactory
    {
        public static async Task<S5Client> CreateAsync(S5Settings settings, IPEndPoint proxy, CancellationTokenSource? cts = null)
        {
            cts ??= new CancellationTokenSource();
            var token = cts.Token;

            var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(proxy, token);
            var stream = tcpClient.GetStream();

            var pair = await S5Protocol.SendHandshakeAsync(stream, settings, token);

            if (pair.success)
            {
                return new S5Client(tcpClient, pair.encryption, cts);
            }

            throw new Exception("Connection error");
        }
    }
}
