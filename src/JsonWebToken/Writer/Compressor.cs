﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken.Compression
{
    /// <summary>Provides compression services.</summary>
    public abstract class Compressor
    {
        internal static Compressor Null = new NullCompressor();

        /// <summary>Compresses the data.</summary>
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
