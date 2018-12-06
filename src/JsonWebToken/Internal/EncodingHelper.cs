// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

#if NETSTANDARD2_0
using System;
using System.Buffers;
using System.ComponentModel;
using System.Text;

namespace JsonWebToken.Internal
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class EncodingHelper
    {
        public static unsafe string GetUtf8String(ReadOnlySpan<byte> input)
        {
            fixed (byte* ptr = input)
            {
                return Encoding.UTF8.GetString(ptr, input.Length);
            }
        }

        public static void GetUtf8Bytes(string input, Span<byte> output)
        {
            GetUtf8Bytes(input.AsSpan(), output);
        }

        public static unsafe int GetUtf8Bytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            fixed (char* inputPtr = input)
            fixed (byte* outputPtr = output)
            {
                return Encoding.UTF8.GetBytes(inputPtr, input.Length, outputPtr, output.Length);
            }
        }

        public static void GetAsciiBytes(string input, Span<byte> output)
        {
            GetAsciiBytes(input.AsSpan(), output);
        }

        public static unsafe void GetAsciiBytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            fixed (char* inputPtr = input)
            fixed (byte* outputPtr = output)
            {
                Encoding.ASCII.GetBytes(inputPtr, input.Length, outputPtr, output.Length);
            }
        }

        internal static unsafe void GetAsciiBytes(ReadOnlySpan<byte> rawHeader, Span<byte> header)
        {
            char[] headerArrayToReturn = null;
            try
            {
                Span<char> utf8Header = header.Length < Constants.MaxStackallocBytes
                ? stackalloc char[header.Length]
                : (headerArrayToReturn = ArrayPool<char>.Shared.Rent(header.Length)).AsSpan(0, header.Length);

                fixed (byte* rawPtr = rawHeader)
                fixed (char* utf8Ptr = utf8Header)
                fixed (byte* header8Ptr = header)
                {
                    Encoding.UTF8.GetChars(rawPtr, rawHeader.Length, utf8Ptr, utf8Header.Length);
                    Encoding.ASCII.GetBytes(utf8Ptr, utf8Header.Length, header8Ptr, header.Length);
                }
            }
            finally
            {
                if (headerArrayToReturn != null)
                {
                    ArrayPool<char>.Shared.Return(headerArrayToReturn);
                }
            }
        }
    }
}
#endif