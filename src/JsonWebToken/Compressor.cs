﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides compression and decompression services.
    /// </summary>
    public abstract class Compressor
    {
        public static readonly Compressor Null = new NullCompressor();

        public abstract Span<byte> Compress(ReadOnlySpan<byte> ciphertext);

        public abstract Span<byte> Decompress(ReadOnlySpan<byte> compressedCiphertext);

        private class NullCompressor : Compressor
        {
            public override Span<byte> Compress(ReadOnlySpan<byte> ciphertext)
            {
                return ciphertext.ToArray();
            }

            public override Span<byte> Decompress(ReadOnlySpan<byte> compressedCiphertext)
            {
                  return compressedCiphertext.ToArray();
            }
        }
    }
}
