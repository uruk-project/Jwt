// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Encodes and Decodes strings as Base64Url.
    /// </summary>
    /// <remarks>Issued from https://github.com/aspnet/.
    /// </remarks>
    public static class Base64Url
    {
        private static readonly Base64 _base64 = Base64.Url;

        private static readonly byte[] EmptyBytes = Array.Empty<byte>();

        /// <summary>
        /// Decodes a string of UTF-8 base64url-encoded text.
        /// </summary>
        public static byte[] Decode(string data)
        {
            if (data == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.data);
            }

            return Decode(Encoding.UTF8.GetBytes(data));
        }

        /// <summary>
        /// Decodes a span of UTF-8 base64url-encoded text.
        /// </summary>
        public static byte[] Decode(ReadOnlySpan<byte> base64Url)
        {
            if (base64Url.IsEmpty)
            {
                return EmptyBytes;
            }

            var dataLength = GetArraySizeRequiredToDecode(base64Url.Length);
            var data = new byte[dataLength];
            Decode(base64Url, data);
            return data;
        }

#if NETSTANDARD2_0
        /// <summary>
        /// Decodes a string of UTF-8 base64url-encoded text into a span of bytes.
        /// </summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(string base64Url, Span<byte> data)
        {
            if (base64Url == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.base64url);
            }

            return Decode(base64Url.AsSpan(), data);
        }
#endif

        /// <summary>
        /// Decodes a span of UTF-8 base64url-encoded text into a span of bytes.
        /// </summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Decode(ReadOnlySpan<char> base64Url, Span<byte> data)
        {
            if (base64Url.IsEmpty)
            {
                return 0;
            }

            byte[] arrayToReturn = null;
            var buffer = base64Url.Length > Constants.MaxStackallocBytes
                ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(base64Url.Length)).AsSpan(0, base64Url.Length)
                : stackalloc byte[base64Url.Length];
            try
            {
#if !NETSTANDARD2_0
                Encoding.UTF8.GetBytes(base64Url, buffer);
#else
                EncodingHelper.GetUtf8Bytes(base64Url, buffer);
#endif
                return Decode(buffer, data);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        /// <summary>
        /// Decodes the span of UTF-8 base64url-encoded text into a span of bytes.
        /// </summary>
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

        /// <summary>
        /// Decodes the span of UTF-8 base64url-encoded text into binary data.
        /// </summary>
        public static OperationStatus Decode(ReadOnlySpan<byte> base64Url, Span<byte> data, out int bytesConsumed, out int bytesWritten)
        {
            // Special-case empty input
            if (base64Url.IsEmpty)
            {
                bytesConsumed = 0;
                bytesWritten = 0;
                return OperationStatus.Done;
            }

            return _base64.Decode(base64Url, data, out bytesConsumed, out bytesWritten);
        }

        /// <summary>
        /// Encodes a span of UTF-8 text into a span of bytes.
        /// </summary>
        /// <returns>The number of the bytes written to <paramref name="base64Url"/>.</returns>
        public static int Encode(ReadOnlySpan<byte> utf8Data, Span<byte> base64Url)
        {
            // Special-case empty input
            if (utf8Data.IsEmpty)
            {
                return 0;
            }

            var status = _base64.Encode(utf8Data, base64Url, out _, out var bytesWritten);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDoneException(status);
            }

            return bytesWritten;
        }

        /// <summary>
        /// Encodes a span of UTF-8 text.
        /// </summary>
        /// <returns>The base64-url encoded string.</returns>
        public static byte[] Encode(ReadOnlySpan<byte> utf8Data)
        {
            // Special-case empty input
            if (utf8Data.IsEmpty)
            {
                return Array.Empty<byte>();
            }

            int base64UrlLength = _base64.GetEncodedLength(utf8Data.Length);
            var utf8Encoded = new byte[base64UrlLength];
            Encode(utf8Data, utf8Encoded);
            return utf8Encoded;
        }

#if NETSTANDARD2_0
        /// <summary>
        /// Encodes a string of UTF-8 text.
        /// </summary>
        /// <returns>The base64-url encoded string.</returns>
        public static byte[] Encode(string data)
        {
            if (data == null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.data);
            }

            return Encode(data.AsSpan());
        }
#endif

        /// <summary>
        /// Encodes a string of UTF-8 text.
        /// </summary>
        /// <returns>The base64-url encoded string.</returns>
        public static byte[] Encode(ReadOnlySpan<char> data)
        {
            byte[] utf8ArrayToReturn = null;
            try
            {
                var utf8Data = data.Length > Constants.MaxStackallocBytes
                    ? (utf8ArrayToReturn = ArrayPool<byte>.Shared.Rent(data.Length)).AsSpan(0, data.Length)
                    : stackalloc byte[data.Length];

                GetUtf8Bytes(data, utf8Data);
                return Encode(utf8Data);
            }
            finally
            {
                if (utf8ArrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturn);
                }
            }
        }

        /// <summary>
        /// Gets the minimum buffer size required for decoding of <paramref name="count"/> characters.
        /// </summary>
        /// <param name="count">The number of characters to decode.</param>
        /// <returns>
        /// The minimum buffer size required for decoding  of <paramref name="count"/> characters.
        /// </returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetArraySizeRequiredToDecode(int count)
        {
            return _base64.GetMaxDecodedLength(count);
        }

        /// <summary>
        /// Gets the minimum output buffer size required for encoding <paramref name="count"/> bytes.
        /// </summary>
        /// <param name="count">The number of characters to encode.</param>
        /// <returns>
        /// The minimum output buffer size required for encoding <paramref name="count"/> <see cref="byte"/>s.
        /// </returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetArraySizeRequiredToEncode(int count)
        {
            return _base64.GetEncodedLength(count);
        }

#if !NETSTANDARD2_0
        private static int GetUtf8Bytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            return Encoding.UTF8.GetBytes(input, output);
        }
#else
        private static int GetUtf8Bytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            return EncodingHelper.GetUtf8Bytes(input, output);
        }

        private static string GetUtf8String(ReadOnlySpan<byte> input)
        {
            return EncodingHelper.GetUtf8String(input);
        }
#endif
    }
}