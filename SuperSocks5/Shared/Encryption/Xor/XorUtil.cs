namespace SuperSocks5.Shared.Encryption.Xor
{
    public static class XorUtil
    {
        private static readonly byte[] _patterns =
        [
            0x59, 0x5A, 0x5B, 0x5D, 0x5F, 0x95, 0x99, 0x9A, 0x9B, 0x9D, 0x9F, 0xA5, 0xA9, 0xAA, 0xAB, 0xAD, 0xAF, 0xB5,
            0xB9, 0xBA, 0xBB, 0xBD, 0xBF, 0xD5, 0xD9, 0xDA, 0xDB, 0xDD, 0xDF, 0xF5, 0xF9, 0xFA, 0xFB, 0xFD, 0xFF
        ];

        private static byte GetPatternByte(int i, int patternNum)
        {
            return _patterns[(patternNum + i) % _patterns.Length];
        }

        private static int GetRotateAmount(int i, int patternNum)
        {
            return (patternNum + i) % 3 + 1;
        }

        private static byte[] EncodeMessageInner(byte[] bytes, int len)
        {
            List<byte> result = new();

            var patternNum = (byte)Random.Shared.Next(0, _patterns.Length);
            var encoded = EncodeBytes(bytes, patternNum);

            //encryption identifier
            result.Add((byte)Random.Shared.Next(XorHandshakeEncryption.MinInclusive, XorHandshakeEncryption.MaxExclusive)); //xor id
            result.Add((byte)Random.Shared.Next(0, 256));

            switch (len)
            {
                case 4:
                    result.AddRange(BitConverter.GetBytes(encoded.Length));
                    break;
                case 2:
                    result.AddRange(BitConverter.GetBytes((short)encoded.Length));
                    break;
                case 1:
                    result.Add((byte)encoded.Length);
                    break;
                default:
                    Console.WriteLine("messageLen == 0");
                    throw new Exception("messageLen == 0");
            }

            result.Add(patternNum);
            result.AddRange(encoded);
            return result.ToArray();
        }

        public static byte[] EncodeMessage1(byte[] bytes)
        {
            return EncodeMessageInner(bytes, 1);
        }

        public static byte[] EncodeMessage4(byte[] bytes)
        {
            return EncodeMessageInner(bytes, 4);
        }

        private static async Task<byte[]> DecodeMessageInner(Stream stream, bool skipId, int len, CancellationToken token)
        {
            if (!skipId)
            {
                var skipBuffer = new byte[2];
                await stream.ReadExactlyAsync(skipBuffer, 0, 2, token);
            }

            int messageLen;
            byte[] lenBuffer;

            switch (len)
            {
                case 4:
                    lenBuffer = new byte[4];
                    await stream.ReadExactlyAsync(lenBuffer, 0, lenBuffer.Length, token);
                    messageLen = BitConverter.ToInt32(lenBuffer);
                    break;
                case 2:
                    lenBuffer = new byte[2];
                    await stream.ReadExactlyAsync(lenBuffer, 0, lenBuffer.Length, token);
                    messageLen = BitConverter.ToInt16(lenBuffer);
                    break;
                case 1:
                    lenBuffer = new byte[1];
                    await stream.ReadExactlyAsync(lenBuffer, 0, lenBuffer.Length, token);
                    messageLen = lenBuffer[0];
                    break;
                default:
                    Console.WriteLine("messageLen == 0");
                    throw new Exception("messageLen == 0");
            }

            var patternNum = new byte[1];
            await stream.ReadExactlyAsync(patternNum, 0, 1, token);

            var encodedMessage = new byte[messageLen];
            await stream.ReadExactlyAsync(encodedMessage, 0, encodedMessage.Length, token);
            var decodedHeader = DecodeBytes(encodedMessage, patternNum[0]);
            return decodedHeader;
        }


        public static async Task<byte[]> DecodeMessage4(Stream stream, bool skipId, CancellationToken token)
        {
            return await DecodeMessageInner(stream, skipId, 4, token);
        }
        
        public static async Task<byte[]> DecodeMessage1(Stream stream, bool skipId, CancellationToken token)
        {
            return await DecodeMessageInner(stream, skipId, 1, token);
        }

        public static async Task<MemoryStream> DecodeStream4(Stream stream, bool skipId, CancellationToken token)
        {
            return new MemoryStream(await DecodeMessage4(stream, skipId, token));
        }
        
        public static async Task<MemoryStream> DecodeStream1(Stream stream, bool skipId, CancellationToken token)
        {
            return new MemoryStream(await DecodeMessage1(stream, skipId, token));
        }

        private static byte[] EncodeBytes(byte[] bytes, byte patternNum)
        {
            var output = new byte[bytes.Length * 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                var xorByte = (byte)(bytes[i] ^ GetPatternByte(i, patternNum));
                xorByte = byte.RotateLeft(xorByte, GetRotateAmount(i, patternNum));
                output[i * 2] = (byte)xorByte;
                output[i * 2 + 1] = (byte)Random.Shared.Next(0, 256);
            }

            return output;
        }

        private static byte[] DecodeBytes(byte[] modBytes, byte patternNum)
        {
            var bytes = new byte[modBytes.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                var readByte = modBytes[i * 2];
                readByte = byte.RotateRight(readByte, GetRotateAmount(i, patternNum));
                bytes[i] = (byte)(readByte ^ GetPatternByte(i, patternNum));
            }

            return bytes;
        }
    }
}
