// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.IO;
using System.IO.Compression;

namespace JsonWebToken
{
    internal sealed class DeflateCompressor : Compressor<DeflateStream>
    {
        public override DeflateStream CreateCompressionStream(Stream outputStream)
        {
            return new DeflateStream(outputStream, CompressionLevel.Optimal, false);
        }
    }

    internal sealed class DeflateDecompressor : Decompressor<DeflateStream>
    {
        public override DeflateStream CreateDecompressionStream(Stream inputStream)
        {
            return new DeflateStream(inputStream, CompressionMode.Decompress);
        }
    }
}
