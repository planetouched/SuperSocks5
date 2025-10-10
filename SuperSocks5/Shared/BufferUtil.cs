namespace SuperSocks5.Shared;

public static class BufferUtil
{
    public static async Task<byte[]> ReadToEnd(Stream stream, CancellationToken token, int bufferSize = 4096)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[bufferSize];

        int bytesRead;
        while ((bytesRead = await stream.ReadAsync(buffer, 0, bufferSize, token)) > 0)
        {
            ms.Write(buffer, 0, bytesRead);
        }

        return ms.ToArray();
    }
}