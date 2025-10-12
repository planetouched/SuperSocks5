using System.Net;
using SuperSocks5.Shared.Encryption._Base;
using SuperSocks5.Shared.Encryption.None;

namespace SuperSocks5.Shared.Settings;

public class S5Settings
{
    //the latter have higher priority => new NoneAuthCredentials(), new UsernamePasswordAuthCredentials("admin", "admin"), etc
    //if you want security you must necessarily remove NoneAuthCredentials 
    public List<AuthCredentialsBase> ResponseAuths { get; } = new()
    {
        new NoneCredentials()
    };

    public List<AuthCredentialsBase> RequestAuths { get; } = new()
    {
        new NoneCredentials()
    };

    public IPAddress RemoteServerAddress { get; set; } = IPAddress.Parse("127.0.0.1");

    public IPEndPoint? UpstreamProxy { get; set; }

    public static bool DebugInfo { get; set; } = true;
}