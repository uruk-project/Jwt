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
        /// Compresses the data.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="destination"></param>
        /// <returns></returns>
        public abstract int  Compress(ReadOnlySpan<byte> data, Span<byte> destination);

        /// <summary>
        /// Decompresses the compressed data.
        /// </summary>
        /// <param name="compressedData">The compressed data.</param>
        /// <param name="bufferWritter">The destination <see cref="IBufferWriter{T}"/>.</param>
        /// <returns></returns>
        public abstract void Decompress(ReadOnlySpan<byte> compressedData, IBufferWriter<byte> bufferWritter);
     
        private sealed class NullCompressor : Compressor
        {
            public override Span<byte> Compress(ReadOnlySpan<byte> data)
            {
                throw new NotImplementedException();
            }

            public override int Compress(ReadOnlySpan<byte> data, Span<byte> destination)
            {
                return 0;
            }

            public override void Decompress(ReadOnlySpan<byte> compressedData, IBufferWriter<byte> bufferWritter)
            {
            }
        }
    }
}
