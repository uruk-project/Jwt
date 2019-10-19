// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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
#if !NETSTANDARD2_0 && !NET461
                compressionStream.Write(ciphertext);
#else
            compressionStream.Write(ciphertext.ToArray(), 0, ciphertext.Length);
#endif
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
                var segment = new DecompressionSegment(memory);
                segment.RunningIndex = RunningIndex + Memory.Length;
                Next = segment;
                return segment;
            }
        }

        /// <inheritdoc />
        public override unsafe ReadOnlySequence<byte> Decompress(ReadOnlySpan<byte> compressedCiphertext)
        {
            fixed (byte* pinnedCompressedCiphertext = compressedCiphertext)
            {
                using var inputStream = new UnmanagedMemoryStream(pinnedCompressedCiphertext, compressedCiphertext.Length, compressedCiphertext.Length, FileAccess.Read);
                using var compressionStream = CreateDecompressionStream(inputStream);
                var buffer = new byte[Constants.DecompressionBufferLength];
                DecompressionSegment? firstSegment = null;
                DecompressionSegment? segment = null;
                int uncompressedLength = 0;
                int readData;
                while ((readData = compressionStream.Read(buffer, 0, Constants.DecompressionBufferLength)) != 0)
                {
                    uncompressedLength += readData;
                    if (firstSegment is null)
                    {
                        firstSegment = new DecompressionSegment(buffer.AsMemory(0, readData));
                    }
                    else
                    {
                        segment = (segment ?? firstSegment).Add(buffer.AsMemory(0, readData));
                    }

                    if (readData < Constants.DecompressionBufferLength)
                    {
                        break;
                    }

                    buffer = new byte[Constants.DecompressionBufferLength];
                }

                if (segment is null)
                {
                    return new ReadOnlySequence<byte>(buffer.AsMemory(0, readData));
                }
                else
                {
                    return new ReadOnlySequence<byte>(firstSegment!, 0, segment, readData);
                }
            }
        }
    }
}
