using SuperSocks5.Examples;

namespace SuperSocks5
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