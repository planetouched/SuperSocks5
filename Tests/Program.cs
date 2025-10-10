using SuperSocks5.Examples;
using Tests.Examples;

namespace Tests
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            await TcpProxyChain.WithAuth();
            await UdpProxyChain.WithAuth();

            Console.ReadKey();
        }
    }
}
