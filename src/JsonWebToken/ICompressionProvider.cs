using System;
using System.IO;
using System.IO.Compression;

namespace JsonWebToken
{
    public static class CompressionAlgorithms
    {
        public const string Deflate = "DEF";
        public const string GZip = "ZIP";
        public const string Brotli = "BRO";
    }

    public abstract class CompressionProvider
    {
        public static readonly CompressionProvider Deflate = new DeflateCompressionProvider();

        public static readonly CompressionProvider GZip = new GZipCompressionProvider();

#if NETCOREAPP2_1
        public static readonly CompressionProvider Brotli = new BrotliCompressionProvider();
#endif

        public abstract Span<byte> Compress(ReadOnlySpan<byte> ciphertext);

        public abstract Span<byte> Decompress(ReadOnlySpan<byte> compressedCiphertext);

        public static CompressionProvider CreateCompressionProvider(string compressionAlgorithm)
        {
            switch (compressionAlgorithm)
            {
                case CompressionAlgorithms.Deflate:
                    return Deflate;
                case CompressionAlgorithms.GZip:
                    return GZip;
#if NETCOREAPP2_1
                case CompressionAlgorithms.Brotli:
                    return Brotli;
#endif
            }

            return null;
        }
    }

#if NETCOREAPP2_1
    public class BrotliCompressionProvider : CompressionProvider<BrotliStream>
    {
        public override BrotliStream CreateCompressionStream(Stream outputStream)
        {
            return new BrotliStream(outputStream, CompressionLevel.Optimal, false);
        }

        public override BrotliStream CreateDecompressionStream(Stream inputStream)
        {
            return new BrotliStream(inputStream, CompressionMode.Decompress);
        }
    }
#endif

    public class GZipCompressionProvider : CompressionProvider<GZipStream>
    {
        public override GZipStream CreateCompressionStream(Stream outputStream)
        {
            return new GZipStream(outputStream, CompressionLevel.Optimal, false);
        }

        public override GZipStream CreateDecompressionStream(Stream inputStream)
        {
            return new GZipStream(inputStream, CompressionMode.Decompress);
        }
    }

    public class DeflateCompressionProvider : CompressionProvider<DeflateStream>
    {
        public override DeflateStream CreateCompressionStream(Stream outputStream)
        {
            return new DeflateStream(outputStream, CompressionLevel.Optimal, false);
        }

        public override DeflateStream CreateDecompressionStream(Stream inputStream)
        {
            return new DeflateStream(inputStream, CompressionMode.Decompress);
        }
    }

    public abstract class CompressionProvider<TStream> : CompressionProvider where TStream : Stream
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
            const int bufferLength = 1024;
            int uncompressedLength = 0;
            var buffer = new byte[bufferLength];
            using (var inputStream = new MemoryStream(compressedCiphertext.ToArray()))
            {
                using (var compressionStream = CreateDecompressionStream(inputStream))
                {
                    int readData = 0;
                    while ((readData = compressionStream.Read(buffer, uncompressedLength, bufferLength)) != 0)
                    {
                        uncompressedLength += readData;
                        if (readData < bufferLength)
                        {
                            break;
                        }

                        if (uncompressedLength == buffer.Length)
                        {
                            Array.Resize(ref buffer, buffer.Length * 2);
                        }
                    }

                    return buffer.AsSpan().Slice(0, uncompressedLength);
                }
            }
        }
    }
}
