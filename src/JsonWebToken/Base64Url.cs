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
    /// <remarks>Issued from https://github.com/aspnet/.</remarks>
    public static class Base64Url
    {
        private static readonly IBase64Url _base64 = new SoftwareBase64Url();

        private static readonly byte[] EmptyBytes = Array.Empty<byte>();

        /// <summary>
        /// Decodes a string of UTF-8 base64url-encoded text.
        /// </summary>
        public static byte[] Base64UrlDecode(string input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            return Base64UrlDecode(Encoding.UTF8.GetBytes(input));
        }

        /// <summary>
        /// Decodes a span of UTF-8 base64url-encoded text.
        /// </summary>
        public static byte[] Base64UrlDecode(ReadOnlySpan<byte> base64Url)
        {
            if (base64Url.IsEmpty)
            {
                return EmptyBytes;
            }

            var dataLength = GetArraySizeRequiredToDecode(base64Url.Length);
            var data = new byte[dataLength];
            Base64UrlDecode(base64Url, data);
            return data;
        }

#if NETSTANDARD2_0
        /// <summary>
        /// Decodes a string of UTF-8 base64url-encoded text into a span of bytes.
        /// </summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Base64UrlDecode(string base64Url, Span<byte> data)
        {
            if (base64Url == null)
            {
                throw new ArgumentNullException(nameof(base64Url));
            }

            return Base64UrlDecode(base64Url.AsSpan(), data);
        }
#endif

        /// <summary>
        /// Decodes a span of UTF-8 base64url-encoded text into a span of bytes.
        /// </summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        public static int Base64UrlDecode(ReadOnlySpan<char> base64Url, Span<byte> data)
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
                return Base64UrlDecode(buffer, data);
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
        public static int Base64UrlDecode(ReadOnlySpan<byte> base64Url, Span<byte> data)
        {
            var status = Base64UrlDecode(base64Url, data, out _, out int bytesWritten);
            if (status != OperationStatus.Done)
            {
                JwtThrowHelper.ThrowOperationNotDone(status);
            }

            return bytesWritten;
        }

        /// <summary>
        /// Decodes the span of UTF-8 base64url-encoded text into binary data.
        /// </summary>
        public static OperationStatus Base64UrlDecode(ReadOnlySpan<byte> base64Url, Span<byte> data, out int bytesConsumed, out int bytesWritten)
        {
            // Special-case empty input
            if (base64Url.IsEmpty)
            {
                bytesConsumed = 0;
                bytesWritten = 0;
                return OperationStatus.Done;
            }

            return _base64.DecodeFromUtf8(base64Url, data, out bytesConsumed, out bytesWritten);
        }

        /// <summary>
        /// Encodes a span of UTF-8 text into a span of bytes.
        /// </summary>
        /// <returns>The number of the bytes written to <paramref name="base64Url"/>.</returns>
        public static int Base64UrlEncode(ReadOnlySpan<byte> utf8Data, Span<byte> base64Url)
        {
            // Special-case empty input
            if (utf8Data.IsEmpty)
            {
                return 0;
            }

            var status = _base64.EncodeToUtf8(utf8Data, base64Url, out _, out var bytesWritten);
            if (status != OperationStatus.Done)
            {
                JwtThrowHelper.ThrowOperationNotDone(status);
            }

            return bytesWritten;
        }

        /// <summary>
        /// Encodes a span of UTF-8 text.
        /// </summary>
        /// <returns>The base64-url encoded string.</returns>
        public static byte[] Base64UrlEncode(ReadOnlySpan<byte> utf8Data)
        {
            // Special-case empty input
            if (utf8Data.IsEmpty)
            {
                return Array.Empty<byte>();
            }

            int base64UrlLength = _base64.GetMaxEncodedToUtf8Length(utf8Data.Length);
            var utf8Encoded = new byte[base64UrlLength];
            Base64UrlEncode(utf8Data, utf8Encoded);
            return utf8Encoded;
        }

#if NETSTANDARD2_0
        /// <summary>
        /// Encodes a string of UTF-8 text.
        /// </summary>
        /// <returns>The base64-url encoded string.</returns>
        public static byte[] Base64UrlEncode(string data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            return Base64UrlEncode(data.AsSpan());
        }
#endif

        /// <summary>
        /// Encodes a string of UTF-8 text.
        /// </summary>
        /// <returns>The base64-url encoded string.</returns>
        public static byte[] Base64UrlEncode(ReadOnlySpan<char> data)
        {
            byte[] utf8ArrayToReturn = null;
            try
            {
                var utf8Data = data.Length > Constants.MaxStackallocBytes
                    ? (utf8ArrayToReturn = ArrayPool<byte>.Shared.Rent(data.Length)).AsSpan(0, data.Length)
                    : stackalloc byte[data.Length];

                GetUtf8Bytes(data, utf8Data);
                return Base64UrlEncode(utf8Data);
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
            return _base64.GetMaxDecodedFromUtf8Length(count);
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
            return _base64.GetMaxEncodedToUtf8Length(count);
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