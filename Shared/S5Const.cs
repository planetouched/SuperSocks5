namespace SuperSocks5.Shared;

public static class S5Const
{
    public const byte CmdConnect = 0x01;
    public const byte CmdBind = 0x02;
    public const byte CmdUdpAssociate = 0x03;

    public const byte IPv4 = 0x01;
    public const byte DomainName = 0x03;
    public const byte IPv6 = 0x04;

    public const byte Version = 0x05;

    public const byte AuthNoAcceptableMethods = 0xFF;

    public const byte NoError = 0x00;
    
    public const byte ErrorGeneralSocksServerFailure = 0x01;
    public const byte ErrorConnectionNotAllowedByRuleset = 0x02;
    public const byte ErrorNetworkUnreachable = 0x03;
    public const byte ErrorHostUnreachable = 0x04;
    public const byte ErrorConnectionRefused = 0x05;
    public const byte ErrorTtlExpired = 0x06;
    public const byte ErrorCommandNotSupported = 0x07;
    public const byte ErrorAddressTypeNotSupported = 0x08;
}