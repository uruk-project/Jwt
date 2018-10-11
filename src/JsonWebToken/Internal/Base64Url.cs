using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Encodes and Decodes strings as Base64Url encoding.
    /// </summary>
    /// <remarks>Issued from https://github.com/aspnet/
    /// </remarks>
    public static class Base64Url
    {
        private static readonly IBase64Url _base64 = new SoftwareBase64Url();

        private static readonly byte[] EmptyBytes = new byte[0];

        /// <summary>
        /// Decodes a base64url-encoded string.
        /// </summary>
        /// <remarks>
        /// The input must not contain any whitespace or padding characters.
        /// Throws <see cref="FormatException"/> if the input is malformed.
        /// </remarks>
        public static byte[] Base64UrlDecode(string input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            return Base64UrlDecode(Encoding.UTF8.GetBytes(input));
        }

        /// <summary>
        /// Decodes a base64url-encoded span of chars.
        /// </summary>
        /// <remarks>
        /// The input must not contain any whitespace or padding characters.
        /// Throws <see cref="FormatException"/> if the input is malformed.
        /// </remarks>
        private static byte[] Base64UrlDecode(ReadOnlySpan<byte> base64Url)
        {
            // Special-case empty input
            if (base64Url.IsEmpty)
            {
                return EmptyBytes;
            }

            var dataLength = GetArraySizeRequiredToDecode(base64Url.Length);
            var data = new byte[dataLength];
            var status = _base64.DecodeFromUtf8(base64Url, data, out int consumed, out int written);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDone(status);
            }

            Debug.Assert(base64Url.Length == consumed);
            Debug.Assert(data.Length == written);

            return data;
        }

        /// <summary>
        /// Decodes a base64url-encoded span of chars into a span of bytes.
        /// </summary>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        /// <remarks>
        /// The input must not contain any whitespace or padding characters.
        /// Throws <see cref="FormatException"/> if the input is malformed.
        /// </remarks>
        public static int Base64UrlDecode(string base64Url, Span<byte> data)
        {
            byte[] arrayToReturn = null;
            var buffer = base64Url.Length > Constants.MaxStackallocBytes
                ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(base64Url.Length)).AsSpan(0, base64Url.Length)
                : stackalloc byte[base64Url.Length];
            try
            {
#if NETCOREAPP2_1
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

        public static int Base64UrlDecode(ReadOnlySpan<byte> base64Url, Span<byte> data)
        {
            // Special-case empty input
            if (base64Url.IsEmpty)
            {
                return 0;
            }

            var status = _base64.DecodeFromUtf8(base64Url, data, out int consumed, out int written);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDone(status);
            }

            Debug.Assert(base64Url.Length == consumed);
            Debug.Assert(data.Length >= written);

            return written;
        }

        /// <summary>
        /// Decode the span of UTF-8 base64url-encoded text into binary data.
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

        public static int Base64UrlEncode(ReadOnlySpan<byte> utf8EncodedHeader, Span<byte> base64EncodedHeader)
        {
            // Special-case empty input
            if (utf8EncodedHeader.IsEmpty)
            {
                return 0;
            }

            var status = _base64.EncodeToUtf8(utf8EncodedHeader, base64EncodedHeader, out var bytesConsumed, out var bytesWritten);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDone(status);
            }

            return bytesWritten;
        }

        public static string Base64UrlEncode(ReadOnlySpan<byte> data)
        {
            // Special-case empty input
            if (data.IsEmpty)
            {
                return string.Empty;
            }

            byte[] arrayToReturn = null;
            int base64UrlLength = _base64.GetMaxEncodedToUtf8Length(data.Length);
            try
            {
                var utf8Encoded = base64UrlLength > Constants.MaxStackallocBytes
                    ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(base64UrlLength)).AsSpan(0, base64UrlLength)
                    : stackalloc byte[base64UrlLength];

                _base64.EncodeToUtf8(data, utf8Encoded, out var bytesConsumed, out var bytesWritten);
#if NETCOREAPP2_1
                return Encoding.UTF8.GetString(utf8Encoded);
#else
                return EncodingHelper.GetUtf8String(utf8Encoded);
#endif
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
        }

        public static string Base64UrlEncode(string data)
        {
            byte[] utf8ArrayToReturn = null;
            byte[] b64ArrayToReturn = null;
            try
            {
                var utf8Encoded = data.Length > Constants.MaxStackallocBytes
                    ? (utf8ArrayToReturn = ArrayPool<byte>.Shared.Rent(data.Length)).AsSpan(0, data.Length)
                    : stackalloc byte[data.Length];

                int bytesCount = GetUtf8Bytes(data, utf8Encoded);
                int base64UrlLength = _base64.GetMaxEncodedToUtf8Length(bytesCount);
                var base64Encoded = base64UrlLength > Constants.MaxStackallocBytes
                    ? (b64ArrayToReturn = ArrayPool<byte>.Shared.Rent(base64UrlLength)).AsSpan(0, base64UrlLength)
                    : stackalloc byte[base64UrlLength];

                _base64.EncodeToUtf8(utf8Encoded, base64Encoded, out var bytesConsumed, out var bytesWritten);

                return GetUtf8String(base64Encoded);
            }
            finally
            {
                if (utf8ArrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturn);
                }

                if (b64ArrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(b64ArrayToReturn);
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

#if NETCOREAPP2_1
        private static int GetUtf8Bytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            return Encoding.UTF8.GetBytes(input, output);
        }

        private static string GetUtf8String(ReadOnlySpan<byte> bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }
#else
        private static int GetUtf8Bytes(ReadOnlySpan<char> input, Span<byte> output)
        {
            return EncodingHelper.GetUtf8Bytes(input, output);
        }

        private static int GetUtf8Bytes(string input, Span<byte> output)
        {
            return GetUtf8Bytes(input.AsSpan(), output);
        }

        private static string GetUtf8String(ReadOnlySpan<byte> input)
        {
            return EncodingHelper.GetUtf8String(input);
        }
#endif
    }
}