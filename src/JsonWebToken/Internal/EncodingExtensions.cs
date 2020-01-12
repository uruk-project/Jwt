// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NETSTANDARD2_0 || NET461
using System;
using System.ComponentModel;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Helper class for encoding text.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    internal static class EncodingExtensions
    {
        /// <summary>
        /// Gets the string representation of the <paramref name="input"/>. 
        /// </summary>
        /// <param name="encoding"></param>
        /// <param name="input"></param>
        /// <returns></returns>
        public static unsafe string GetString(this Encoding encoding, ReadOnlySpan<byte> input)
        {
            fixed (byte* ptr = input)
            {
                return encoding.GetString(ptr, input.Length);
            }
        }

        /// <summary>
        /// Gets the bytes sequence of the <paramref name="input"/>.
        /// </summary>
        /// <param name="encoding"></param>
        /// <param name="input"></param>
        /// <param name="output"></param>
        public static int GetBytes(this Encoding encoding, string input, Span<byte> output)
        {
            return encoding.GetBytes(input.AsSpan(), output);
        }

        /// <summary>
        /// Gets the bytes sequence of the <paramref name="input"/>.
        /// </summary>
        /// <param name="encoding"></param>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <returns></returns>
        public static unsafe int GetBytes(this Encoding encoding, ReadOnlySpan<char> input, Span<byte> output)
        {
            fixed (char* inputPtr = input)
            fixed (byte* outputPtr = output)
            {
                return encoding.GetBytes(inputPtr, input.Length, outputPtr, output.Length);
            }
        }

        /// <summary>
        /// Gets the char sequence of the <paramref name="input"/>.
        /// </summary>
        /// <param name="encoding"></param>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <returns></returns>
        public static unsafe int GetChars(this Encoding encoding, ReadOnlySpan<byte> input, Span<char> output)
        {
            fixed (byte* inputPtr = input)
            fixed (char* outputPtr = output)
            {
                return encoding.GetChars(inputPtr, input.Length, outputPtr, output.Length);
            }
        }
    }
}
#endif