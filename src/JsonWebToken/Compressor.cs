using System;

namespace JsonWebToken
{
    public abstract class Compressor
    {
        public static readonly Compressor Deflate = new DeflateCompressor();

//        public static readonly Compressor GZip = new GZipCompressor();

//#if NETCOREAPP2_1
//        public static readonly Compressor Brotli = new BrotliCompressor();
//#endif

        public abstract Span<byte> Compress(ReadOnlySpan<byte> ciphertext);

        public abstract Span<byte> Decompress(ReadOnlySpan<byte> compressedCiphertext);

        public static Compressor Create(string compressionAlgorithm)
        {
            switch (compressionAlgorithm)
            {
                case CompressionAlgorithms.Deflate:
                    return Deflate;
                //case CompressionAlgorithms.GZip:
                //    return GZip;
#if NETCOREAPP2_1
                //case CompressionAlgorithms.Brotli:
                //    return Brotli;
#endif
            }

            return null;
        }
    }
}
