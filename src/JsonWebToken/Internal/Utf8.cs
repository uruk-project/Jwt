// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Text;

namespace JsonWebToken
{
    internal static class Utf8
    {
        private static readonly UTF8Encoding Encoder = new UTF8Encoding(false, false);

        public static int GetBytes(ReadOnlySpan<char> chars, Span<byte> bytes)
            => Encoder.GetBytes(chars, bytes);

        public static int GetBytes(string s, Span<byte> bytes)
            => Encoder.GetBytes(s, bytes);

        public static byte[] GetBytes(string s)
            => Encoder.GetBytes(s);

        public static string GetString(ReadOnlySpan<byte> bytes)
            => Encoder.GetString(bytes);

        public static int GetMaxByteCount(int charCount)
            => Encoder.GetMaxByteCount(charCount);

        public static int GetMaxCharCount(int byteCount)
            => Encoder.GetMaxCharCount(byteCount);

        public static int GetChars(ReadOnlySpan<byte> bytes, Span<char> chars)
            => Encoder.GetChars(bytes, chars);
    }
}