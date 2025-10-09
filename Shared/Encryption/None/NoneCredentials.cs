using SuperSocks5.Shared.Encryption._Base;

namespace SuperSocks5.Shared.Encryption.None;

public class NoneCredentials : AuthCredentialsBase
{
    public NoneCredentials() : base(AuthMethodType.None)
    {
    }

    public override EncryptionBase GetEncryption()
    {
        return new NoEncryption();
    }
}