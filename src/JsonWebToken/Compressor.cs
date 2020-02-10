// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;

namespace JsonWebToken
{
    /// <summary>
    /// Provides compression and decompression services.
    /// </summary>
    public abstract class Compressor
    {
        internal static Compressor Null = new NullCompressor();

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
        public abstract ReadOnlySequence<byte> Decompress(ReadOnlySpan<byte> compressedData);

        private class NullCompressor : Compressor
        {
            public override Span<byte> Compress(ReadOnlySpan<byte> data)
            {
                throw new NotImplementedException();
            }

            public override ReadOnlySequence<byte> Decompress(ReadOnlySpan<byte> compressedData)
            {
                throw new NotImplementedException();
            }
        }
    }
}
