using System;

namespace JsonWebToken
{
    public abstract class CompressionProvider
    {
        public static readonly CompressionProvider Deflate = new DeflateCompressionProvider();

//        public static readonly CompressionProvider GZip = new GZipCompressionProvider();

//#if NETCOREAPP2_1
//        public static readonly CompressionProvider Brotli = new BrotliCompressionProvider();
//#endif

        public abstract Span<byte> Compress(ReadOnlySpan<byte> ciphertext);

        public abstract Span<byte> Decompress(ReadOnlySpan<byte> compressedCiphertext);

        public static CompressionProvider CreateCompressionProvider(string compressionAlgorithm)
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
