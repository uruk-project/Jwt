// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

//using System.IO;
//using System.IO.Compression;

//namespace JsonWebToken.Internal
//{
//#if NETCOREAPP2_1
//    public sealed class BrotliCompressor : Compressor<BrotliStream>
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
