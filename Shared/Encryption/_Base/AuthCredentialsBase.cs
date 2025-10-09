using System.Net.Sockets;

namespace SuperSocks5.Shared.Encryption._Base;

public abstract class AuthCredentialsBase
{
    public byte AuthType { get; protected set; }
        
    protected AuthCredentialsBase(byte authType)
    {
        AuthType = authType;
    }

    public virtual async Task<bool> Authenticate(NetworkStream stream, CancellationToken token)
    {
        return true;
    }

    public virtual async Task<bool> Validate(NetworkStream stream, CancellationToken token)
    {
        return true;
    }

    public abstract EncryptionBase GetEncryption();
}