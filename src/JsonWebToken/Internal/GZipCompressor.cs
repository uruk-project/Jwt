//using System.IO;
//using System.IO.Compression;

//namespace JsonWebToken.Internal
//{
//    public class GZipCompressor : Compressor<GZipStream>
//    {
//        public override GZipStream CreateCompressionStream(Stream outputStream)
//        {
//            return new GZipStream(outputStream, CompressionLevel.Optimal, false);
//        }

//        public override GZipStream CreateDecompressionStream(Stream inputStream)
//        {
//            return new GZipStream(inputStream, CompressionMode.Decompress);
//        }
//    }
//}
