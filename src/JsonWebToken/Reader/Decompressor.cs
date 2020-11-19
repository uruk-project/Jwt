// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;

namespace JsonWebToken
{
    /// <summary>Provides decompression services.</summary>
    public abstract class Decompressor
    {
        internal static Decompressor Null = new NullDecompressor();

        /// <summary>Decompresses the compressed data.</summary>
        /// <param name="compressedData">The compressed data.</param>
        /// <param name="bufferWritter">The destination <see cref="IBufferWriter{T}"/>.</param>
        /// <returns></returns>
        public abstract void Decompress(ReadOnlySpan<byte> compressedData, IBufferWriter<byte> bufferWritter);

        private sealed class NullDecompressor : Decompressor
        {
            public override void Decompress(ReadOnlySpan<byte> compressedData, IBufferWriter<byte> bufferWritter)
            {
            }
        }
    }
}
