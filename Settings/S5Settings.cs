using System.Net;
using SuperSocks5.Shared.Encryption._Base;
using SuperSocks5.Shared.Encryption.None;

namespace SuperSocks5.Settings;

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

    public IPEndPoint? UpstreamProxy { get; set; }
}