// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
