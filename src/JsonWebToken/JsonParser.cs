// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting Base64Url JSON data into a <see cref="Dictionary{TKey, TValue}"/>
    /// </summary>
    public static partial class JsonParser
    {
        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="Dictionary{TKey, TValue}"/>.
        /// </summary>
        /// <param name="buffer"></param>
        public static Dictionary<string, object> Parse(ReadOnlySpan<byte> buffer)
        {
            return ReadJson(buffer);
        }
    }
}
