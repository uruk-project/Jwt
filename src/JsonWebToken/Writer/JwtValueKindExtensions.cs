// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
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