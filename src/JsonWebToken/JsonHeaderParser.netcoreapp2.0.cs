// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if !NETCOREAPP3_0
using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    public static partial class JsonHeaderParser
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static JwtHeader ReadJsonHeader(ReadOnlySpan<byte> buffer)
        {
            return new JwtHeader(JsonParser.ReadJson(buffer));
        }
    }
}
#endif
