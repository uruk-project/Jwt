// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides compression and decompression services.
    /// </summary>
    public abstract class Compressor
    {
        /// <summary>
        /// Compresses the data.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public abstract Span<byte> Compress(ReadOnlySpan<byte> data);

        /// <summary>
        /// Decompresses the compressed data.
        /// </summary>
        /// <param name="compressedData">The compressed data.</param>
        /// <returns></returns>
        public abstract Span<byte> Decompress(ReadOnlySpan<byte> compressedData);

        private class NullCompressor : Compressor
        {
            public override Span<byte> Compress(ReadOnlySpan<byte> data)
            {
                return data.ToArray();
            }

            public override Span<byte> Decompress(ReadOnlySpan<byte> compressedData)
            {
                  return compressedData.ToArray();
            }
        }
    }
}
