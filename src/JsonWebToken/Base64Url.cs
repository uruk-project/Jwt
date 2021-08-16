// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
    /// <summary>Encodes and decodes strings as Base64Url.</summary>
    public static class Base64Url
    {
        /// <summary>Decodes a string of UTF-8 base64url-encoded text.</summary>
        /// <remarks>This method allocate an array of bytes. Use <see cref="Decode(ReadOnlySpan{byte}, Span{byte})"/> when possible.</remarks>
        public static byte[] Decode(string data)
        {
            if (data is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.data);
            }

            int length = Utf8.GetMaxByteCount(data.Length);
            byte[]? utf8ArrayToReturn = null;
            try
            {
                Span<byte> tmp = length > Constants.MaxStackallocBytes
                    ? (utf8ArrayToReturn = ArrayPool<byte>.Shared.Rent(length))
                    : stackalloc byte[Constants.MaxStackallocBytes];
                int written = Utf8.GetBytes(data, tmp);
                return Decode(tmp.Slice(0, written));
            }
            finally
            {
                if (utf8ArrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturn);
                }
            }
        }

        /// <summary>Decodes a span of UTF-8 base64url-encoded text.</summary>
        /// <remarks>This method allocate an array of bytes. Use <see cref="Decode(ReadOnlySpan{byte}, Span{byte})"/> when possible.</remarks>
        public static byte[] Decode(ReadOnlySpan<byte> base64Url)
        {
            var dataLength = GetArraySizeRequiredToDecode(base64Url.Length);
            var data = new byte[dataLength];
            Decode(base64Url, data);
            return data;
        }

#if NETSTANDARD2_0
        /// <summary>Decodes a string of UTF-8 base64url-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(string base64Url, Span<byte> data)
        {
            if (base64Url is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.base64url);
            }

            return Decode(base64Url.AsSpan(), data);
        }
#endif

        /// <summary>Decodes a span of UTF-8 base64url-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(ReadOnlySpan<char> base64Url, Span<byte> data)
        {
            byte[]? arrayToReturn = null;
            var buffer = base64Url.Length > Constants.MaxStackallocBytes
                ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(base64Url.Length))
                : stackalloc byte[Constants.MaxStackallocBytes];
            try
            {
                int length = Utf8.GetBytes(base64Url, buffer);
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

        /// <summary>Decodes the span of UTF-8 base64url-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(ReadOnlySpan<byte> base64Url, Span<byte> data)
        {
            var status = Decode(base64Url, data, out _, out int bytesWritten);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDoneException(status);
            }

            return bytesWritten;
        }

        /// <summary>Decodes the span of UTF-8 base64url-encoded text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        /// <remarks>Does not verify the operation result.</remarks>
        internal static int DecodeUnsafe(ReadOnlySpan<byte> base64Url, Span<byte> data)
        {
            var status = Decode(base64Url, data, out _, out int bytesWritten);
            Debug.Assert(status == OperationStatus.Done);

            return bytesWritten;
        }

        /// <summary>Decodes the span of UTF-8 base64url-encoded text into binary data.</summary>
        public static OperationStatus Decode(ReadOnlySpan<byte> base64Url, Span<byte> data, out int bytesConsumed, out int bytesWritten)
            => gfoidl.Base64.Base64.Url.Decode(base64Url, data, out bytesConsumed, out bytesWritten);

        /// <summary>Encodes a span of UTF-8 text into a span of bytes.</summary>
        /// <returns>The number of the bytes written to <paramref name="base64Url"/>.</returns>
        public static int Encode(ReadOnlySpan<byte> utf8Data, Span<byte> base64Url)
        {
            var status = gfoidl.Base64.Base64.Url.Encode(utf8Data, base64Url, out _, out var bytesWritten);
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
            int base64UrlLength = gfoidl.Base64.Base64.Url.GetEncodedLength(utf8Data.Length);
            var utf8Encoded = new byte[base64UrlLength];
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
            => gfoidl.Base64.Base64.Url.GetMaxDecodedLength(count);

        /// <summary>Gets the output buffer size required for encoding <paramref name="count"/> bytes.</summary>
        /// <param name="count">The number of characters to encode.</param>
        /// <returns>The output buffer size required for encoding <paramref name="count"/> <see cref="byte"/>s.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetArraySizeRequiredToEncode(int count)
            => gfoidl.Base64.Base64.Url.GetEncodedLength(count);

#if NET461 || NET47 || NETSTANDARD
        internal static unsafe bool IsBase64UrlString(string value)
            => IsBase64UrlString(value.AsSpan());
#endif

        internal static unsafe bool IsBase64UrlString(ReadOnlySpan<char> value)
        {
            for (int i = 0; i < value.Length; i++)
            {
                if (!IsValidBase64UrlChar(value[i]))
                {
                    return false;
                }
            }

            return true;

            static bool IsValidBase64UrlChar(char value)
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
                            // - or _
                            if (byteValue == (byte)'-' || byteValue == (byte)'_')
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