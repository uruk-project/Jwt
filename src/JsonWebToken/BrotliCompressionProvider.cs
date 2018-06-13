//using System.IO;
//using System.IO.Compression;

//namespace JsonWebToken
//{
//#if NETCOREAPP2_1
//    public class BrotliCompressionProvider : CompressionProvider<BrotliStream>
//    {
//        public override BrotliStream CreateCompressionStream(Stream outputStream)
//        {
//            return new BrotliStream(outputStream, CompressionLevel.Optimal, false);
//        }

//        public override BrotliStream CreateDecompressionStream(Stream inputStream)
//        {
//            return new BrotliStream(inputStream, CompressionMode.Decompress);
//        }
//    }
//#endif
//}
