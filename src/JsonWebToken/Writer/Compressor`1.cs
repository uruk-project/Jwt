// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.IO;

namespace JsonWebToken.Compression
{
    /// <summary>Provides compression services, based on <typeparamref name="TStream"/>.</summary>
    public abstract class Compressor<TStream> : Compressor where TStream : Stream
    {
        /// <summary>Creates a compression <see cref="Stream"/>.</summary>
        public abstract TStream CreateCompressionStream(Stream inputStream);

        /// <inheritdoc />
        public override unsafe int Compress(ReadOnlySpan<byte> ciphertext, Span<byte> destination)
        {
            int compressedBytes;
            fixed (byte* pinnedCiphertext = destination)
            {
                using var outputStream = new UnmanagedMemoryStream(pinnedCiphertext, destination.Length, destination.Length, FileAccess.Write);
                using var compressionStream = CreateCompressionStream(outputStream);
                compressionStream.Write(ciphertext);
                compressionStream.Flush();
                compressionStream.Close();
                compressedBytes = (int)outputStream.Position + 1;
                outputStream.Close();
            }

            return compressedBytes;
        }
    }
}
