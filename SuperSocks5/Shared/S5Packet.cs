using System.Net;

namespace SuperSocks5.Shared;

public struct S5Packet
{
    public string TargetHost;
    public int TargetPort;
    public IPAddress? IpAddress;
    public byte Command;
    public byte Error;
    public byte[] Payload;
    public byte FrameNum;

    public IPEndPoint? GetEndPoint()
    {
        if (IpAddress != null)
        {
            return new IPEndPoint(IpAddress, TargetPort);
        }

        return null;
    }

    // static bool TheSameBoth(IPAddress ip1, IPAddress ip2)
    // {
    //     if (ip1 == null && ip2 == null)
    //     {
    //         return true;
    //     }
    //
    //     if (ip1 != null && ip2 != null)
    //     {
    //         return ip1.Equals(ip2);
    //     }
    //
    //     return false;
    // }
    //
    // public bool Compare(S5Packet other)
    // {
    //     return TargetHost == other.TargetHost && TargetPort == other.TargetPort && TheSameBoth(IpAddress, other.IpAddress);
    // }
}