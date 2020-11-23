// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Specifies the data type of a JSON value within a JWT.</summary>
    public enum JwtValueKind : byte
    {
        /// <summary>There is no value (as distinct from <see cref="Null"/>).</summary>
        Undefined = 0x00,

        /// <summary>A JSON object.</summary>
        Object = 0x02,

        /// <summary>A JSON array.</summary>
        Array = 0x04,

        /// <summary>A JSON string.</summary>
        String = 0x08,

        /// <summary>A JSON encoded string.</summary>
        JsonEncodedString = 0x09,

        /// <summary>A 32 bits signed integer JSON number.</summary>
        Int32 = 0x81,

        /// <summary>A 64 bits signed integer JSON number.</summary>
        Int64 = 0x82,

        /// <summary>A 32 bits unsigned integer JSON number.</summary>
        UInt32 = 0x83,

        /// <summary>A 64 bits unsigned integer JSON number.</summary>
        UInt64 = 0x84,

        /// <summary>A 32 bits floating point JSON number.</summary>
        Float = 0x41,

        /// <summary>A 64 bits floating point JSON number.</summary>
        Double = 0x42,

        /// <summary>The JSON value true.</summary>
        True = 0x21,

        /// <summary>The JSON value false.</summary>
        False = 0x22,

        /// <summary>The JSON value null.</summary>
        Null = 0x10
    }

    internal static class JwtValueKindExtensions
    {
        public static bool IsNumber(this JwtValueKind kind)
        {
            return ((uint)kind & 0xc0) != 0x00;
        }

        public static bool IsInteger(this JwtValueKind kind)
        {
            return ((uint)kind & 0x80) != 0x00;
        }
        
        public static bool IsFloat(this JwtValueKind kind)
        {
            return ((uint)kind & 0x40) != 0x00;
        }

        public static bool IsString(this JwtValueKind kind)
        {
            return ((uint)kind & 0x08) != 0x00;
        }

        public static bool IsStringOrArray(this JwtValueKind kind)
        {
            return ((uint)kind & 0x0c) != 0x00;
        }
    }
}