// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if !NETCOREAPP3_0
using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    public static partial class JsonPayloadParser
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static JwtPayload ReadJsonPayload(ReadOnlySpan<byte> buffer)
        {
            return new JwtPayload(JsonParser.ReadJson(buffer));
        }
    }
}
#endif
