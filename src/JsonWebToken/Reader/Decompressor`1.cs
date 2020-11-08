// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.IO;

namespace JsonWebToken
{
    /// <summary>
    /// Provides decompression services, based on <typeparamref name="TStream"/>.
    /// </summary>
    public abstract class Decompressor<TStream> : Decompressor where TStream : Stream
    {
        /// <summary>
        /// Creates a decompression <see cref="Stream"/>.
        /// </summary>
        public abstract TStream CreateDecompressionStream(Stream inputStream);

        /// <inheritsdoc/>
        public override unsafe void Decompress(ReadOnlySpan<byte> compressedData, IBufferWriter<byte> bufferWritter)
        {
            fixed (byte* pinnedCompressedCiphertext = compressedData)
            {
                using var inputStream = new UnmanagedMemoryStream(pinnedCompressedCiphertext, compressedData.Length, compressedData.Length, FileAccess.Read);
                using var compressionStream = CreateDecompressionStream(inputStream);
                var buffer = bufferWritter.GetSpan(Constants.DecompressionBufferLength);
                int uncompressedLength = 0;
                int readData;
                while ((readData = compressionStream.Read(buffer)) != 0)
                {
                    uncompressedLength += readData;
                    bufferWritter.Advance(readData);
                    if (readData < buffer.Length)
                    {
                        break;
                    }

                    buffer = bufferWritter.GetSpan(Constants.DecompressionBufferLength);
                }
            }
        }
    }
}
