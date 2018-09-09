using System;
using System.IO;

namespace JsonWebToken
{
    public abstract class Compressor<TStream> : Compressor where TStream : Stream
    {
        public abstract TStream CreateDecompressionStream(Stream outputStream);

        public abstract TStream CreateCompressionStream(Stream outputStream);

        public override Span<byte> Compress(ReadOnlySpan<byte> ciphertext)
        {
            using (var outputStream = new MemoryStream())
            using (var compressionStream = CreateCompressionStream(outputStream))
            {
#if NETCOREAPP2_1
                compressionStream.Write(ciphertext);
#else
                compressionStream.Write(ciphertext.ToArray(), 0, ciphertext.Length);
#endif
                compressionStream.Flush();
                compressionStream.Close();
                return outputStream.ToArray();
            }
        }

        public override Span<byte> Decompress(ReadOnlySpan<byte> compressedCiphertext)
        {
            using (var inputStream = new MemoryStream(compressedCiphertext.ToArray()))
            using (var compressionStream = CreateDecompressionStream(inputStream))
            {
                var buffer = new byte[Constants.DecompressionBufferLength];
                int uncompressedLength = 0;
                int readData;
                while ((readData = compressionStream.Read(buffer, uncompressedLength, Constants.DecompressionBufferLength)) != 0)
                {
                    uncompressedLength += readData;
                    if (readData < Constants.DecompressionBufferLength)
                    {
                        break;
                    }

                    if (uncompressedLength == buffer.Length)
                    {
                        Array.Resize(ref buffer, buffer.Length * 2);
                    }
                }

                return new Span<byte>(buffer, 0, uncompressedLength);
            }
        }
    }
}
