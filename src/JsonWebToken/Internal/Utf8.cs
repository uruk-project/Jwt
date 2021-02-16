// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
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

#if DEBUG
        internal static void AssertMagicNumber(ushort magicNumber, string value)
        {
            if (value.Length < sizeof(ushort))
            {
                value = value.PadRight(sizeof(ushort), '\0');
            }

            Debug.Assert(magicNumber == BitConverter.ToUInt16(Encoding.UTF8.GetBytes(value), 0));
        }

        internal static void AssertMagicNumber(uint magicNumber, string value)
        {
            if (value.Length < sizeof(uint))
            {
                value = value.PadRight(sizeof(uint), '\0');
            }

            Debug.Assert(magicNumber == BitConverter.ToUInt32(Encoding.UTF8.GetBytes(value), 0));
        }

        internal static void AssertMagicNumber(ulong magicNumber, string value)
        {
            if (value.Length < sizeof(ulong))
            {
                value = value.PadRight(sizeof(ulong), '\0');
            }

            Debug.Assert(magicNumber == BitConverter.ToUInt64(Encoding.UTF8.GetBytes(value), 0));
        }
#endif
    }
}