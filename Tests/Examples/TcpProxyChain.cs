using System.Net;
using System.Text;
using SuperSocks5.Client;
using SuperSocks5.Examples.Xor;
using SuperSocks5.Server;
using SuperSocks5.Shared;
using SuperSocks5.Shared.Encryption._Base;
using SuperSocks5.Shared.Encryption.AESGcm;
using SuperSocks5.Shared.Encryption.None;
using SuperSocks5.Shared.Settings;

namespace Tests.Examples
{
    static class TcpProxyChain
    {
        private static AuthCredentialsBase GetCreds(string credType)
        {
            if (credType == "xor")
            {
                return new UserPassXorCredentials("user", "password");
            }
            if (credType == "up")
            {
                return new UserPassCredentials("user", "password");
            }
            if (credType == "aes")
            {
                var aesKey = Convert.FromHexString("A5F697E5D7416EBED99E8EC7031B63E2F7DB1C4284CE7E2DD3FD0D2935A662F6");
                return new AesGcmUserPassCredentials("user", "password", aesKey);
            }
            if (credType == "aesTime")
            {
                var aesKey = Convert.FromHexString("A5F697E5D7416EBED99E8EC7031B63E2F7DB1C4284CE7E2DD3FD0D2935A662F6");
                return new AesGcmKeyTimeCredentials("superkey", aesKey, 5000);
            }

            return new NoneCredentials();
        }

        public static async Task Test()
        {
            var serverSettings = new S5Settings();
            
            serverSettings.ResponseAuths.Add(GetCreds("aesTime"));
            serverSettings.RequestAuths.Add(GetCreds("aes"));
            
            serverSettings.UpstreamProxy = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1083); //to next proxy
            var server = new S5Server(IPAddress.Any, 1082, serverSettings);

            var server1Settings = new S5Settings();
            
            server1Settings.ResponseAuths.Add(GetCreds("aes"));
            //server1Settings.RequestAuths.Add(GetCreds("aes"));
            
            var server1 = new S5Server(IPAddress.Any, 1083, server1Settings);
            server1.OnRedirect += ServerOnOnRedirect1; //redirect method ... see below

            var server2Settings = new S5Settings();
            
            server2Settings.ResponseAuths.Add(GetCreds("aes"));
            server2Settings.RequestAuths.Add(GetCreds("aes"));
            
            var server2 = new S5Server(IPAddress.Any, 1084, server2Settings);

            Task.Run(() => { server.StartAsync(); });
            Task.Run(() => { server1.StartAsync(); });
            Task.Run(() => { server2.StartAsync(); });

            await Task.Delay(500);

            var clientSettings = new S5Settings();
            clientSettings.RequestAuths.Add(GetCreds("aesTime"));

            var uri = new Uri("http://example.com");
            string requestString = $"GET {uri.AbsolutePath} HTTP/1.1\r\n" +
                                   $"Host: {uri.Host}\r\n" +
                                   $"Connection: close\r\n" +
                                   $"\r\n";

            byte[] requestBytes = Encoding.ASCII.GetBytes(requestString);

            var result = await S5Client.SendRequestTcpAsync(
                clientSettings.RequestAuths, 
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1082), 
                new S5Packet { TargetHost = "example.com", TargetPort = 80 }, 
                requestBytes);

            await File.WriteAllBytesAsync("1.html", result);

            Console.WriteLine($"result len: {result.Length}");
        }

        public static async Task WithAuth()
        {
            await Test();
        }

        private static async Task<(IPEndPoint?, IList<AuthCredentialsBase>)> ServerOnOnRedirect1(S5Packet packet, CancellationToken token)
        {
            //analyze packet for routing and choosing next proxy
            var requestAuths = new List<AuthCredentialsBase> {GetCreds("aes") };

            return (new(IPAddress.Parse("127.0.0.1"), 1084), requestAuths);
        }
    }
}