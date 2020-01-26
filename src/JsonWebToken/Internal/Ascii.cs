// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text;

namespace JsonWebToken
{
    internal static class Ascii
    {
        private static readonly ASCIIEncoding Encoder = new ASCIIEncoding();

        public static int GetBytes(ReadOnlySpan<char> input, Span<byte> output)
            => Encoder.GetBytes(input, output);
    }
}