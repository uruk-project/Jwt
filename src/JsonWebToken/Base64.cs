// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>Encodes and decodes strings as Base64.</summary>
    public static class Base64
    {
        /// <summary>Decodes a span of UTF-8 base64-encoded text.</summary>
        /// <remarks>This method allocate an array of bytes. Use <see cref="Decode(ReadOnlySpan{byte}, Span{byte})"/> when possible.</remarks>
        public static byte[] Decode(ReadOnlySpan<byte> base64)
        {
            var dataLength = GetArraySizeRequiredToDecode(base64.Length);
            var data = new byte[dataLength];
            int length = Decode(base64, data);
            if (length != dataLength)
            {
                data = data.AsSpan(0, length).ToArray();
            }

            return data;
        }

#if NETSTANDARD2_0
        /// <summary>Decodes a string of UTF-8 base64-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(string base64, Span<byte> data)
        {
            if (base64 is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.base64url);
            }

            return Decode(base64.AsSpan(), data);
        }
#endif

        /// <summary>Decodes a span of UTF-8 base64-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(ReadOnlySpan<char> base64, Span<byte> data)
        {
            byte[]? arrayToReturn = null;
            var buffer = base64.Length > Constants.MaxStackallocBytes
                ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(base64.Length))
                : stackalloc byte[Constants.MaxStackallocBytes];
            try
            {
                int length = Utf8.GetBytes(base64, buffer);
                return Decode(buffer.Slice(0, length), data);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        /// <summary>Decodes the span of UTF-8 base64-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(ReadOnlySpan<byte> base64, Span<byte> data)
        {
            var status = Decode(base64, data, out _, out int bytesWritten);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDoneException(status);
            }

            return bytesWritten;
        }

        /// <summary>Decodes the span of UTF-8 base64-encoded text into binary data.</summary>
        public static OperationStatus Decode(ReadOnlySpan<byte> base64, Span<byte> data, out int bytesConsumed, out int bytesWritten)
        {
            int lastWhitespace = base64.LastIndexOfAny(WhiteSpace);
            if (lastWhitespace == -1)
            {
                return gfoidl.Base64.Base64.Default.Decode(base64, data, out bytesConsumed, out bytesWritten);
            }
            else
            {
                byte[]? utf8ArrayToReturn = null;
                Span<byte> utf8Data = base64.Length > Constants.MaxStackallocBytes
                    ? (utf8ArrayToReturn = ArrayPool<byte>.Shared.Rent(base64.Length))
                    : stackalloc byte[Constants.MaxStackallocBytes];
                try
                {
                    int firstWhitespace = base64.IndexOfAny(WhiteSpace);
                    int length = 0;
                    Span<byte> buffer = utf8Data;
                    if (firstWhitespace != lastWhitespace)
                    {
                        while (firstWhitespace != -1)
                        {
                            base64.Slice(0, firstWhitespace).CopyTo(buffer);
                            buffer = buffer.Slice(firstWhitespace);
                            length += firstWhitespace;

                            // Skip whitespaces
                            int i = firstWhitespace;
                            while (++i < base64.Length && IsWhiteSpace(base64[i])) ;

                            base64 = base64.Slice(i);
                            firstWhitespace = base64.IndexOfAny(WhiteSpace);
                        }

                        //// Copy the remaining
                        base64.CopyTo(buffer);
                        length += base64.Length;
                    }
                    else
                    {
                        base64.Slice(0, firstWhitespace).CopyTo(buffer);
                        base64.Slice(firstWhitespace + 1).CopyTo(buffer.Slice(firstWhitespace));
                        length = base64.Length - 1;
                    }

                    return gfoidl.Base64.Base64.Default.Decode(utf8Data.Slice(0, length), data, out bytesConsumed, out bytesWritten);
                }
                finally
                {
                    if (utf8ArrayToReturn != null)
                    {
                        ArrayPool<byte>.Shared.Return(utf8ArrayToReturn);
                    }
                }
            }
        }

        private static bool IsWhiteSpace(byte c)
            => c == ' ' || (c >= '\t' && c <= '\r');

        private static ReadOnlySpan<byte> WhiteSpace
            => new byte[] { (byte)' ', (byte)'\t', (byte)'\n', (byte)'\v', (byte)'\f', (byte)'\r' };

        /// <summary>Encodes a span of UTF-8 text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="base64"/>.</returns>
        public static int Encode(ReadOnlySpan<byte> utf8Data, Span<byte> base64)
        {
            var status = gfoidl.Base64.Base64.Default.Encode(utf8Data, base64, out _, out var bytesWritten);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDoneException(status);
            }

            return bytesWritten;
        }

        /// <summary>Encodes a span of UTF-8 text.</summary>
        /// <returns>The base64-url encoded string.</returns>
        /// <remarks>This method allocate an array of bytes. Use <see cref="Encode(ReadOnlySpan{byte}, Span{byte})"/> when possible.</remarks>
        public static byte[] Encode(ReadOnlySpan<byte> utf8Data)
        {
            int base64Length = gfoidl.Base64.Base64.Default.GetEncodedLength(utf8Data.Length);
            var utf8Encoded = new byte[base64Length];
            Encode(utf8Data, utf8Encoded);
            return utf8Encoded;
        }

#if NETSTANDARD2_0 || NET47
        /// <summary>Encodes a string of UTF-8 text.</summary>
        /// <returns>The base64-url encoded string.</returns>
        /// <remarks>This method allocate an array of bytes. Use <see cref="Encode(ReadOnlySpan{byte}, Span{byte})"/> when possible.</remarks>
        public static byte[] Encode(string data)
        {
            if (data is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.data);
            }

            return Encode(data.AsSpan());
        }
#endif

        /// <summary>Encodes a string of UTF-8 text.</summary>
        /// <returns>The base64-url encoded string.</returns>
        /// <remarks>This method allocate an array of bytes. Use <see cref="Encode(ReadOnlySpan{byte}, Span{byte})"/> when possible.</remarks>
        public static byte[] Encode(ReadOnlySpan<char> data)
        {
            byte[]? utf8ArrayToReturn = null;
            try
            {
                int length = Utf8.GetMaxByteCount(data.Length);
                var utf8Data = length > Constants.MaxStackallocBytes
                    ? (utf8ArrayToReturn = ArrayPool<byte>.Shared.Rent(length))
                    : stackalloc byte[Constants.MaxStackallocBytes];

                int written = Utf8.GetBytes(data, utf8Data);
                return Encode(utf8Data.Slice(0, written));
            }
            finally
            {
                if (utf8ArrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturn);
                }
            }
        }

        /// <summary>Gets the minimum buffer size required for decoding of <paramref name="count"/> characters.</summary>
        /// <param name="count">The number of characters to decode.</param>
        /// <returns>The minimum buffer size required for decoding  of <paramref name="count"/> characters.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetArraySizeRequiredToDecode(int count)
            => gfoidl.Base64.Base64.Default.GetMaxDecodedLength(count);

        /// <summary>Gets the output buffer size required for encoding <paramref name="count"/> bytes.</summary>
        /// <param name="count">The number of characters to encode.</param>
        /// <returns>The output buffer size required for encoding <paramref name="count"/> <see cref="byte"/>s.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetArraySizeRequiredToEncode(int count)
            => gfoidl.Base64.Base64.Default.GetEncodedLength(count);

#if NET462 || NET47 || NETSTANDARD
        internal static unsafe bool IsBase64String(string value)
            => IsBase64String(value.AsSpan());
#endif

        internal static unsafe bool IsBase64String(ReadOnlySpan<char> value)
        {
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (!IsValidBase64Char(c))
                {
                    if (c != '=' || i < value.Length - 2)
                    {
                        return false;
                    }
                }
            }

            return true;

            static bool IsValidBase64Char(char value)
            {
                bool result = false;
                if (value <= byte.MaxValue)
                {
                    byte byteValue = (byte)value;

                    // 0-9
                    if (byteValue >= (byte)'0' && byteValue <= (byte)'9')
                    {
                        result = true;
                    }
                    else
                    {
                        // a-z or A-Z
                        byte letter = (byte)(byteValue | 0x20);
                        if (letter >= (byte)'a' && letter <= (byte)'z')
                        {
                            result = true;
                        }
                        else
                        {
                            // + or / or whitespaces
                            if (byteValue == (byte)'+' || byteValue == (byte)'/' || IsWhiteSpace(byteValue))
                            {
                                result = true;
                            }
                        }
                    }
                }

                return result;
            }
        }
    }
}