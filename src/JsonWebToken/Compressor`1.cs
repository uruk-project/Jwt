// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.IO;

namespace JsonWebToken
{
    /// <summary>
    /// Provides compression and decompression services, based on <typeparamref name="TStream"/>.
    /// </summary>
    public abstract class Compressor<TStream> : Compressor where TStream : Stream
    {
        /// <summary>
        /// Creates a decompression <see cref="Stream"/>.
        /// </summary>
        public abstract TStream CreateDecompressionStream(Stream inputStream);

        /// <summary>
        /// Creates a compression <see cref="Stream"/>.
        /// </summary> 
        public abstract TStream CreateCompressionStream(Stream inputStream);

        /// <inheritdoc />
        public override Span<byte> Compress(ReadOnlySpan<byte> ciphertext)
        {
            using var outputStream = new MemoryStream();
            using var compressionStream = CreateCompressionStream(outputStream);
            compressionStream.Write(ciphertext);
            compressionStream.Flush();
            compressionStream.Close();
            return outputStream.ToArray();
        }

        private sealed class DecompressionSegment : ReadOnlySequenceSegment<byte>
        {
            public DecompressionSegment(ReadOnlyMemory<byte> memory)
            {
                Memory = memory;
            }

            public DecompressionSegment Add(ReadOnlyMemory<byte> memory)
            {
                var segment = new DecompressionSegment(memory)
                {
                    RunningIndex = RunningIndex + Memory.Length
                };
                Next = segment;
                return segment;
            }
        }

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
