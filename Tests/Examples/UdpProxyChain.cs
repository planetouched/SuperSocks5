using System.Net;
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
    static class UdpProxyChain
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

        public static async Task Test(string credType)
        {
            var serverSettings = new S5Settings();
            
            serverSettings.ResponseAuths.Add(GetCreds(credType));
            serverSettings.RequestAuths.Add(GetCreds(credType));
            
            serverSettings.UpstreamProxy = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1093); //to next proxy
            var server = new S5Server(IPAddress.Any, 1092, serverSettings);

            var server1Settings = new S5Settings();
            
            server1Settings.ResponseAuths.Add(GetCreds(credType));
            //server1Settings.RequestAuths.Add(GetCreds(credType));
            
            var server1 = new S5Server(IPAddress.Any, 1093, server1Settings);
            server1.OnRedirect += ServerOnOnRedirect1; //redirect method see below...

            var server2Settings = new S5Settings();
            
            server2Settings.ResponseAuths.Add(GetCreds(credType));
            server2Settings.RequestAuths.Add(GetCreds(credType));
            
            var server2 = new S5Server(IPAddress.Any, 1094, server2Settings);

            Task.Run(() => { server.StartAsync(); });
            Task.Run(() => { server1.StartAsync(); });
            Task.Run(() => { server2.StartAsync(); });

            await Task.Delay(1000);

            var clientSettings = new S5Settings();
            clientSettings.RequestAuths.Add(GetCreds(credType));

            byte[] dnsQuery = new byte[]
            {
                // DNS Header (12 bytes)
                0x12, 0x34, // Transaction ID (произвольный ID)
                0x01, 0x00, // Flags: стандартный запрос, рекурсия не запрашивается
                0x00, 0x01, // Questions: 1 вопрос
                0x00, 0x00, // Answer RRs: 0
                0x00, 0x00, // Authority RRs: 0  
                0x00, 0x00, // Additional RRs: 0

                // Question Section
                // Domain: example.com
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example" (7 байт)
                0x03, 0x63, 0x6f, 0x6d, 0x00, // "com" (3 байта) + нулевой терминатор

                // Query Type and Class
                0x00, 0x01, // QTYPE: A record (IPv4 address)
                0x00, 0x01 // QCLASS: IN (Internet)
            };


            var result = await S5Client.SendRequestUdpAsync(clientSettings, 
                new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1092),
                new S5Packet { IpAddress = IPAddress.Parse("8.8.8.8"), TargetPort = 53 }, 
                dnsQuery);

            Console.WriteLine($"result len: {result.Length}");

            File.WriteAllBytes("dns.bin", result);

            await Task.Delay(1000);
        }


        public static async Task WithAuth()
        {
            await Test("aes");
        }

        private static async Task<(IPEndPoint?, IList<AuthCredentialsBase>)> ServerOnOnRedirect1(S5Packet packet, CancellationToken token)
        {
            //analyze packet for routing and choosing next proxy
            var requestAuths = new List<AuthCredentialsBase> { GetCreds("aes") };

            return (new(IPAddress.Parse("127.0.0.1"), 1084), requestAuths);
        }
    }
}