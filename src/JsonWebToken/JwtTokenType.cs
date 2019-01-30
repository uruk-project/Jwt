// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETCOREAPP3_0
using System.Text.Json;
#endif

namespace JsonWebToken
{
    /// <summary>
    /// Specifies the type of token.
    /// </summary>
    public enum JwtTokenType : byte
    {
        /// <summary>
        ///  No token type has been set. Useful?
        /// </summary>
        None = 0,

        /// <summary>
        /// A JSON object.
        /// </summary>
        Object = 1,

        /// <summary>
        /// A JSON array.
        /// </summary>
        Array = 2,

        /// <summary>
        /// An integer value.
        /// </summary>
        Integer = 3,

        /// <summary>
        /// A float value.
        /// </summary>
        Float = 4,

        /// <summary>
        /// A string value.
        /// </summary>
        String = 5,

        /// <summary>
        ///  A boolean value.
        /// </summary>
        Boolean = 6,

        /// <summary>
        ///  A null value. 
        /// </summary>
        Null = 7
    }
}