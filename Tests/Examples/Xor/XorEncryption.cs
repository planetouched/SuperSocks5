using SuperSocks5.Shared.Encryption._Base;
using System.Net.Sockets;

namespace SuperSocks5.Examples.Xor;

public class XorEncryption : EncryptionBase
{
    public override string Name => "Xor";

    private static readonly byte[] _patterns =
    [
        0x59, 0x5A, 0x5B, 0x5D, 0x5F, 0x95, 0x99, 0x9A, 0x9B, 0x9D, 0x9F, 0xA5, 0xA9, 0xAA, 0xAB, 0xAD, 0xAF, 0xB5,
        0xB9, 0xBA, 0xBB, 0xBD, 0xBF, 0xD5, 0xD9, 0xDA, 0xDB, 0xDD, 0xDF, 0xF5, 0xF9, 0xFA, 0xFB, 0xFD, 0xFF
    ];

    private readonly byte _patternNum;

    public XorEncryption(byte patternNum)
    {
        _patternNum = patternNum;
    }

    private byte GetPatternByte(int i)
    {
        return _patterns[(_patternNum + i) % _patterns.Length];
    }

    private int GetRotateAmount(int i)
    {
        return (_patternNum + i) % 3 + 1;
    }

    public byte[] EncodeBytes(byte[] bytes)
    {
        using var writer = new BinaryWriter(new MemoryStream());

        for (int i = 0; i < bytes.Length; i++)
        {
            var xorByte = (byte)(bytes[i] ^ GetPatternByte(i));
            xorByte = byte.RotateLeft(xorByte, GetRotateAmount(i));
            writer.Write(xorByte);
            writer.Write((byte)Random.Shared.Next(1, 256));
        }

        writer.Flush();
        return ((MemoryStream)writer.BaseStream).ToArray();
    }

    public byte[] DecodeBytes(byte[] modBytes)
    {
        using var reader = new BinaryReader(new MemoryStream(modBytes));

        var bytes = new byte[modBytes.Length / 2];

        for (int i = 0; i < bytes.Length; i++)
        {
            var readByte = reader.ReadByte();
            readByte = byte.RotateRight(readByte, GetRotateAmount(i));
            bytes[i] = (byte)(readByte ^ GetPatternByte(i));

            //read empty
            reader.ReadByte();
        }

        return bytes;
    }

    private async Task<byte[]> EncodeMessage(byte[] bytes)
    {
        List<byte> result = new(bytes.Length * 2 + 4);

        var encoded = EncodeBytes(bytes);
        result.AddRange(BitConverter.GetBytes(encoded.Length));
        result.AddRange(encoded);
        return result.ToArray();
    }

    private async Task<Stream> DecodeMessage(Stream stream, CancellationToken token)
    {
        var lenBuffer = new byte[4];
        _ = await stream.ReadAsync(lenBuffer, 0, 4, token);
            
        var encodedMessage = new byte[BitConverter.ToInt32(lenBuffer)];
        _ = await stream.ReadAsync(encodedMessage, 0, encodedMessage.Length, token);
        var decodedHeader = DecodeBytes(encodedMessage);
        return new MemoryStream(decodedHeader);
    }

    private async Task<byte[]> DecodeMessage(byte[] encodedBytes, CancellationToken token)
    {
        using (var memStream = new MemoryStream(encodedBytes))
        {
            var lenBuffer = new byte[4];
            _ = await memStream.ReadAsync(lenBuffer, 0, 4, token);
                
            var encodedMessage = new byte[BitConverter.ToInt32(lenBuffer)];
            _ = await memStream.ReadAsync(encodedMessage, 0, encodedMessage.Length, token);
            var decodedHeader = DecodeBytes(encodedMessage);
            return decodedHeader;
        }
    }

    public override async Task<byte[]> EncodeHeader(byte[] header)
    {
        return await EncodeMessage(header);
    }

    public override async Task<Stream> DecodeHeader(Stream stream, CancellationToken token)
    {
        return await DecodeMessage(stream, token);
    }

    public override async Task<byte[]> EncodeResult(byte[] header)
    {
        return await EncodeMessage(header);
    }

    public override async Task<Stream> DecodeResult(Stream stream, CancellationToken token)
    {
        return await DecodeMessage(stream, token);
    }

    public override byte[] EncodeDatagram(byte[] data)
    {
        return EncodeMessage(data).Result;
    }

    public override byte[] DecodeDatagram(byte[] encodedData, CancellationToken token)
    {
        return DecodeMessage(encodedData, token).Result;
    }

    public override Stream GetEncodingStream(NetworkStream original)
    {
        return new XorStream(original, _patternNum);
    }

    public override Stream GetDecodingStream(NetworkStream original)
    {
        return new XorStream(original, _patternNum);
    }
}