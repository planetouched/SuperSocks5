using System.Net.Sockets;

namespace SuperSocks5.Shared.Encryption.AESGcm
{
    public class AesGcmStream : Stream
    {
        private readonly NetworkStream _baseStream;
        private readonly byte[] _key;
        private byte[]? _buffer;
        private int _bufferOffset;
        private const int MaxSegmentSize = 64 * 1024; // 64KB максимум


        public override bool CanRead => _baseStream.CanRead;
        public override bool CanWrite => _baseStream.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public AesGcmStream(NetworkStream baseStream, byte[] key)
        {
            _baseStream = baseStream;
            _key = key;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token)
        {
            // Если в буфере есть данные - возвращаем их
            if (_buffer != null && _bufferOffset < _buffer.Length)
            {
                int bytesToCopy = Math.Min(count, _buffer.Length - _bufferOffset);
                Buffer.BlockCopy(_buffer, _bufferOffset, buffer, offset, bytesToCopy);
                _bufferOffset += bytesToCopy;

                if (_bufferOffset == _buffer.Length)
                {
                    _buffer = null;
                    _bufferOffset = 0;
                }

                return bytesToCopy;
            }

            // Читаем длину сегмента
            byte[] lengthBuffer = new byte[4];
            int bytesRead = await _baseStream.ReadAsync(lengthBuffer, 0, 4, token);
            if (bytesRead == 0)
            {
                return 0;
            }
            if (bytesRead != 4)
            {
                throw new EndOfStreamException();
            }

            int segmentLength = BitConverter.ToInt32(lengthBuffer, 0);
            if (segmentLength <= 0 || segmentLength > MaxSegmentSize)
            {
                throw new InvalidDataException($"Invalid segment length: {segmentLength}");
            }

            // Читаем полный зашифрованный сегмент
            byte[] encodedData = new byte[segmentLength];
            int totalRead = 0;
            while (totalRead < segmentLength)
            {
                int read = await _baseStream.ReadAsync(encodedData, totalRead, segmentLength - totalRead, token);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                totalRead += read;
            }

            // Дешифруем и сохраняем в буфер
            _buffer = AesGcmEncryption.DecodeBytes(encodedData, _key);
            _bufferOffset = 0;

            // Копируем часть данных в выходной буфер
            int bytesToCopy1 = Math.Min(count, _buffer.Length);
            Buffer.BlockCopy(_buffer, 0, buffer, offset, bytesToCopy1);
            _bufferOffset = bytesToCopy1;

            return bytesToCopy1;
        }


        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token)
        {
            byte[] plaintext = new byte[count];
            Buffer.BlockCopy(buffer, offset, plaintext, 0, count);

            var encodedBytes = AesGcmEncryption.EncodeBytes(plaintext, _key);

            byte[] lengthPrefix = BitConverter.GetBytes(encodedBytes.Length);

            var combinedBuffer = new byte[lengthPrefix.Length + encodedBytes.Length];
            Buffer.BlockCopy(lengthPrefix, 0, combinedBuffer, 0, lengthPrefix.Length);
            Buffer.BlockCopy(encodedBytes, 0, combinedBuffer, lengthPrefix.Length, encodedBytes.Length);

            await _baseStream.WriteAsync(combinedBuffer, 0, combinedBuffer.Length, token);
        }

        public override void Flush()
        {
            _baseStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }
        
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
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
}
