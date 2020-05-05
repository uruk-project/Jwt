// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NETSTANDARD2_0 || NET461 || NET47
using System;
using System.IO;

namespace JsonWebToken
{
    internal static class StreamExtensions
    {
        public static unsafe void Write(this Stream stream, ReadOnlySpan<byte> data)
        {
            stream.Write(data.ToArray(), 0, data.Length);
        }
    }
}
#endif