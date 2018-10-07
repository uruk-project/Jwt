using System;
using System.Buffers;
using System.Diagnostics;
using System.Globalization;
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
        private const int MaxEncodedLength = (int.MaxValue / 4) * 3;  // encode inflates the data by 4/3
        private static readonly IBase64Url _base64 = new SoftwareBase64Url();

        private static readonly byte[] EmptyBytes = new byte[0];

        /// <summary>
        /// Decodes a base64url-encoded string.
        /// </summary>
        /// <param name="input">The base64url-encoded input to decode.</param>
        /// <returns>The base64url-decoded form of the input.</returns>
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
        /// <param name="base64Url">The base64url-encoded input to decode.</param>
        /// <returns>The base64url-decoded form of the input.</returns>
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

        public static string Base64UrlEncode(ReadOnlySpan<byte> data)
        {
            return _base64.EncodeToUtf8(data);
        }

        /// <summary>
        /// Decodes a base64url-encoded span of chars into a span of bytes.
        /// </summary>
        /// <param name="base64Url">A span containing the base64url-encoded input to decode.</param>
        /// <param name="data">The base64url-decoded form of <paramref name="base64Url"/>.</param>
        /// <returns>The number of the bytes written to <paramref name="data"/>.</returns>
        /// <remarks>
        /// The input must not contain any whitespace or padding characters.
        /// Throws <see cref="FormatException"/> if the input is malformed.
        /// </remarks>
        public static int Base64UrlDecode(string base64Url, Span<byte> data)
        {
            return Base64UrlDecode(Encoding.UTF8.GetBytes(base64Url), data);
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

        public static int Base64UrlEncode(ReadOnlySpan<byte> utf8EncodedHeader, Span<byte> base64EncodedHeader)
        {
            var status = _base64.EncodeToUtf8(utf8EncodedHeader, base64EncodedHeader, out var bytesConsumed, out var bytesWritten);
            if (status != OperationStatus.Done)
            {
                ThrowHelper.ThrowOperationNotDone(status);
            }

            return bytesWritten;
        }

        /// <summary>
        /// Decode the span of UTF-8 base64url-encoded text into binary data.
        /// </summary>
        /// <param name="base64Url">The input span which contains UTF-8 base64url-encoded text that needs to be decoded.</param>
        /// <param name="data">The output span which contains the result of the operation, i.e. the decoded binary data.</param>
        /// <param name="bytesConsumed">The number of input bytes consumed during the operation. This can be used to slice the input for subsequent calls, if necessary.</param>
        /// <param name="bytesWritten">The number of bytes written into the output span. This can be used to slice the output for subsequent calls, if necessary.</param>
        /// <param name="isFinalBlock">True (default) when the input span contains the entire data to decode.
        /// Set to false only if it is known that the input span contains partial data with more data to follow.</param>
        /// <returns>It returns the OperationStatus enum values:
        /// - Done - on successful processing of the entire input span
        /// - DestinationTooSmall - if there is not enough space in the output span to fit the decoded input
        /// - NeedMoreData - only if isFinalBlock is false and the input is not a multiple of 4, otherwise the partial input would be considered as InvalidData
        /// - InvalidData - if the input contains bytes outside of the expected base 64 range, or if it contains invalid/more than two padding characters,
        ///   or if the input is incomplete (i.e. not a multiple of 4) and isFinalBlock is true.</returns>
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
        /// Gets the minimum buffer size required for decoding of <paramref name="count"/> characters.
        /// </summary>
        /// <param name="count">The number of characters to decode.</param>
        /// <returns>
        /// The minimum buffer size required for decoding  of <paramref name="count"/> characters.
        /// </returns>
        /// <remarks>
        /// The returned buffer size is large enough to hold <paramref name="count"/> characters as well
        /// as base64 padding characters.
        /// </remarks>
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
        /// <remarks>
        /// The returned buffer size is large enough to hold <paramref name="count"/> bytes as well
        /// as base64 padding characters.
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int GetArraySizeRequiredToEncode(int count)
        {
            return _base64.GetMaxEncodedToUtf8Length(count);
        }
    }
}