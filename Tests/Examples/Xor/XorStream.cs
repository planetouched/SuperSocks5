using System.Net.Sockets;

namespace SuperSocks5.Examples.Xor;

public class XorStream : Stream
{
    private readonly NetworkStream _baseStream;
    private readonly byte _patternNum;

    private static readonly byte[] _patterns =
    [
        0x59, 0x5A, 0x5B, 0x5D, 0x5F, 0x95, 0x99, 0x9A, 0x9B, 0x9D, 0x9F, 0xA5, 0xA9, 0xAA, 0xAB, 0xAD, 0xAF, 0xB5,
        0xB9, 0xBA, 0xBB, 0xBD, 0xBF, 0xD5, 0xD9, 0xDA, 0xDB, 0xDD, 0xDF, 0xF5, 0xF9, 0xFA, 0xFB, 0xFD, 0xFF
    ];

    public override bool CanRead => _baseStream.CanRead;
    public override bool CanWrite => _baseStream.CanWrite;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public XorStream(NetworkStream baseStream, byte patternNum)
    {
        _patternNum = patternNum;
        _baseStream = baseStream;
    }

    private byte GetPatternByte(int i)
    {
        return _patterns[(_patternNum + i) % _patterns.Length];
    }
    
    private int GetRotateAmount(int i)
    {
        return (_patternNum + i) % 3 + 1;
    }
    
    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
    {
        byte[] xorBuffer = new byte[count];
        int bytesRead = await _baseStream.ReadAsync(xorBuffer, 0, count, token);
        for (int i = 0; i < bytesRead; i++)
        {
            var xorByte = xorBuffer[i];
            xorByte = byte.RotateLeft(xorByte, GetRotateAmount(0));
            buffer[offset + i] = (byte)(xorByte ^ GetPatternByte(0));
        }

        return bytesRead;
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
    {
        byte[] xorBuffer = new byte[count];
        for (int i = 0; i < count; i++)
        {
            var xorByte = (byte)(buffer[offset + i] ^ GetPatternByte(0));
            xorByte = byte.RotateRight(xorByte, GetRotateAmount(0));
            xorBuffer[i] = xorByte;
        }

        await _baseStream.WriteAsync(xorBuffer, 0, count, token);
        await _baseStream.FlushAsync(token);
    }

    public override void Flush()
    {
        _baseStream.Flush();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return _baseStream.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }
}