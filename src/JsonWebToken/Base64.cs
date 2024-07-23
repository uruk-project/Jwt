// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>Encodes and decodes strings as Base64.</summary>
    public static class Base64
    {
        /// <summary>Decodes a span of UTF-8 base64-encoded text.</summary>
        /// <remarks>This method allocate an array of bytes. Use <see cref="Decode(ReadOnlySpan{byte}, Span{byte}, bool)"/> when possible.</remarks>
        public static byte[] Decode(ReadOnlySpan<byte> base64, bool stripWhitespace = false)
        {
            var dataLength = GetArraySizeRequiredToDecode(base64.Length);
            var data = new byte[dataLength];
            int length = Decode(base64, data, stripWhitespace);
            if (length != dataLength)
            {
                data = data.AsSpan(0, length).ToArray();
            }

            return data;
        }

#if NETSTANDARD2_0
        /// <summary>Decodes a string of UTF-8 base64-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(string base64, Span<byte> data, bool stripWhitespace = false)
        {
            if (base64 is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.base64url);
            }

            return Decode(base64.AsSpan(), data, stripWhitespace);
        }
#endif

        /// <summary>Decodes a span of UTF-8 base64-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(ReadOnlySpan<char> base64, Span<byte> data, bool stripWhitespace = false)
        {
            byte[]? arrayToReturn = null;
            var buffer = base64.Length > Constants.MaxStackallocBytes
                ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(base64.Length))
                : stackalloc byte[base64.Length];
            try
            {
                int length = Utf8.GetBytes(base64, buffer);
                return Decode(buffer.Slice(0, length), data, stripWhitespace);
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
        public static int Decode(ReadOnlySpan<byte> base64, Span<byte> data, bool stripWhitespace = false)
        {
            var status = Decode(base64, data, out _, out int bytesWritten, stripWhitespace);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDoneException(status);
            }

            return bytesWritten;
        }

        /// <summary>Decodes the span of UTF-8 base64-encoded text into binary data.</summary>
        public static OperationStatus Decode(ReadOnlySpan<byte> base64, Span<byte> data, out int bytesConsumed, out int bytesWritten, bool stripWhitespace = false)
        {
            if (stripWhitespace)
            {
                int lastWhitespace = base64.LastIndexOfAny(WhiteSpace);
                if (lastWhitespace != -1)
                {
                    byte[]? utf8ArrayToReturn = null;
                    Span<byte> utf8Data = base64.Length > Constants.MaxStackallocBytes
                        ? (utf8ArrayToReturn = ArrayPool<byte>.Shared.Rent(base64.Length))
                        : stackalloc byte[base64.Length];
                    try
                    {
                        int length = 0;
                        int i = 0;
                        for (; i <= lastWhitespace; i++)
                        {
                            var current = base64[i];
                            if (!IsWhiteSpace(current))
                            {
                                utf8Data[length++] = current;
                            }
                        }

                        for (; i < base64.Length; i++)
                        {
                            utf8Data[length++] = base64[i];
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

            return gfoidl.Base64.Base64.Default.Decode(base64, data, out bytesConsumed, out bytesWritten);
        }

        private static bool IsWhiteSpace(byte c)
            => c == ' ' || (c >= '\t' && c <= '\r');

        private static ReadOnlySpan<byte> WhiteSpace
            => new byte[] { (byte)' ', (byte)'\t', (byte)'\r', (byte)'\n', (byte)'\v', (byte)'\f' };

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
                    : stackalloc byte[length];

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
                if (value > byte.MaxValue)
                {
                    return false;
                }

                byte byteValue = (byte)value;

                // 0-9
                if (byteValue >= (byte)'0' && byteValue <= (byte)'9')
                {
                    return true;
                }

                // + or /
                if (byteValue == (byte)'+' || byteValue == (byte)'/')
                {
                    return true;
                }

                // a-z or A-Z
                byteValue |= 0x20;
                if (byteValue >= (byte)'a' && byteValue <= (byte)'z')
                {
                    return true;
                }

                return false;
            }
        }
    }
}