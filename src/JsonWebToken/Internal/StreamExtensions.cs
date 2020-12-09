// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NETSTANDARD2_0 || NET461 || NET47
using System;
using System.IO;
using System.Buffers;

namespace JsonWebToken
{
    internal static class StreamExtensions
    {
        public static unsafe void Write(this Stream stream, ReadOnlySpan<byte> data)
        {
            stream.Write(data.ToArray(), 0, data.Length);
        }

        public static int Read(this Stream stream, Span<byte> buffer)
        {
            byte[] sharedBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length);
            try
            {
                int numRead = stream.Read(sharedBuffer, 0, buffer.Length);
                new Span<byte>(sharedBuffer, 0, numRead).CopyTo(buffer);
                return numRead;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(sharedBuffer);
            }
        }
    }
}
#endif