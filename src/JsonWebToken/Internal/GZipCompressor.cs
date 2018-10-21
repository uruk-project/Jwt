// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
