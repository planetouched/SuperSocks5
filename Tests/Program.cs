using System.Text;
using SuperSocks5.Examples;
using SuperSocks5.Shared.Encryption.Xor;
using Tests.Examples;

namespace Tests
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            await TcpProxyChain.WithAuth();
            await UdpProxyChain.WithAuth();

            var bytes1 = XorUtil.EncodeMessage1(Encoding.UTF8.GetBytes("Это тестовая строка! Это тестовая строка! Это тестовая строка!"));
            var decoded1 = await XorUtil.DecodeMessage1(new MemoryStream(bytes1), false, CancellationToken.None);
            Console.WriteLine("decoded1: " + Encoding.UTF8.GetString(decoded1));

            var bytes4 = XorUtil.EncodeMessage4(Encoding.UTF8.GetBytes("Это тестовая строка! Это тестовая строка! Это тестовая строка!"));
            var decoded4 = await XorUtil.DecodeMessage4(new MemoryStream(bytes4), false, CancellationToken.None);
            Console.WriteLine("decoded4: " + Encoding.UTF8.GetString(decoded4));

            Console.ReadKey();
        }
    }
}
