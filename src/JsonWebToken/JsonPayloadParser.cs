// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides methods for converting JWT header JSON data into a <see cref="JwtHeader"/>
    /// </summary>
    public static partial class JsonPayloadParser
    {
        /// <summary>
        /// Parses the UTF-8 <paramref name="buffer"/> as JSON and returns a <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="buffer"></param>
        public static JwtPayload ParsePayload(ReadOnlySpan<byte> buffer)
        {
            return ReadJsonPayload(buffer);
        }
    }
}
