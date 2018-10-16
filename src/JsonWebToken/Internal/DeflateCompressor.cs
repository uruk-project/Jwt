using System.IO;
using System.IO.Compression;

namespace JsonWebToken.Internal
{
    public sealed class DeflateCompressor : Compressor<DeflateStream>
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
}
