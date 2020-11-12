// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>Provides compression services.</summary>
    public abstract class Compressor
    {
        internal static Compressor Null = new NullCompressor();

        /// <summary>Compresses the data.</summary>
        /// <param name="data"></param>
        /// <param name="destination"></param>
        /// <returns></returns>
        public abstract int Compress(ReadOnlySpan<byte> data, Span<byte> destination);

        private sealed class NullCompressor : Compressor
        {
            public override int Compress(ReadOnlySpan<byte> data, Span<byte> destination)
            {
                data.CopyTo(destination);
                return data.Length;
            }
        }
    }
}
