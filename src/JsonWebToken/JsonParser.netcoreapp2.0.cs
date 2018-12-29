// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if !NETCOREAPP3_0
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken
{
    public static partial class JsonParser
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static Dictionary<string, object> ReadJson(ReadOnlySpan<byte> buffer)
        {
#if !NETSTANDARD2_0
            var json = Encoding.UTF8.GetString(buffer);
#else
            var json = Encoding.UTF8.GetString(buffer.ToArray());
#endif
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
        }
    }
}
#endif
