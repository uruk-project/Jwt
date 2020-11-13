// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Specifies the data type of a JSON value within a JWT.</summary>
    public enum JwtValueKind : byte
    {
        /// <summary>There is no value (as distinct from <see cref="Null"/>).</summary>
        Undefined = 0,

        /// <summary>A JSON object.</summary>
        Object = 1,

        /// <summary>A JSON array.</summary>
        Array = 2,

        /// <summary>A JSON string.</summary>
        String = 3,

        /// <summary>A 16 bits integer JSON number.</summary>
        Int16 = 4,

        /// <summary>A 32 bits integer JSON number.</summary>
        Int32 = 5,

        /// <summary>A 64 bits integer JSON number.</summary>
        Int64 = 6,

        /// <summary>A 32 bits floating point JSON number.</summary>
        Float = 7,

        /// <summary>A 64 bits floating point JSON number.</summary>
        Double = 8,

        /// <summary>The JSON value true.</summary>
        True = 9,

        /// <summary>The JSON value false.</summary>
        False = 10,

        /// <summary>The JSON value null.</summary>
        Null = 11
    }
}