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
        private const int MaxStackallocBytes = 256;
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
            var status = Base64UrlDecodeCore(base64Url, data, out int consumed, out int written);
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

            var status = Base64UrlDecodeCore(base64Url, data, out int consumed, out int written);
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
        public static OperationStatus Base64UrlDecode(ReadOnlySpan<byte> base64Url, Span<byte> data, out int bytesConsumed, out int bytesWritten, bool isFinalBlock = true)
        {
            // Special-case empty input
            if (base64Url.IsEmpty)
            {
                bytesConsumed = 0;
                bytesWritten = 0;
                return OperationStatus.Done;
            }

            return Base64UrlDecodeCore(base64Url, data, out bytesConsumed, out bytesWritten, isFinalBlock);
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

        private static OperationStatus Base64UrlDecodeCore(ReadOnlySpan<byte> base64Url, Span<byte> data, out int consumed, out int written, bool isFinalBlock = true)
        {
            return _base64.DecodeFromUtf8(base64Url, data, out consumed, out written);
        }

        private static readonly sbyte[] s_decodingMap =
        {
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
                52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
                -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
                -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
            };
    }

    internal static class ThrowHelper
    {
        public static void ThrowArgumentNullException()
        {
            throw GetArgumentNullException();
        }

        public static void ThrowArgumentOutOfRangeException()
        {
            throw GetArgumentOutOfRangeException();
        }

        public static void ThrowInvalidCountOffsetOrLengthException()
        {
            throw GetInvalidCountOffsetOrLengthException();
        }

        public static void ThrowMalformedInputException(int inputLength)
        {
            throw GetMalformdedInputException(inputLength);
        }

        public static void ThrowOperationNotDone(OperationStatus status)
        {
            throw GetOperationNotDoneException(status);
        }

        public static ArgumentNullException GetArgumentNullException()
        {
            return new ArgumentNullException("length");
        }

        public static ArgumentOutOfRangeException GetArgumentOutOfRangeException()
        {
            return new ArgumentOutOfRangeException("length");
        }

        public static ArgumentException GetInvalidCountOffsetOrLengthException()
        {
            return new ArgumentException(InvalidCountOffsetOrLength, "length");
        }

        private static Exception GetOperationNotDoneException(OperationStatus status)
        {
            switch (status)
            {
                case OperationStatus.DestinationTooSmall:
                    return new InvalidOperationException(DestinationTooSmall);
                case OperationStatus.InvalidData:
                    return new FormatException(InvalidInput);
                default:                                // This case won't happen.
                    throw new NotSupportedException();  // Just in case new states are introduced
            }
        }

        private static FormatException GetMalformdedInputException(int inputLength)
        {
            return new FormatException(FormatMalformedInput(inputLength));
        }


        /// <summary>
        /// Invalid {0}, {1} or {2} length.
        /// </summary>
        internal static readonly string InvalidCountOffsetOrLength = "Invalid length.";

        /// <summary>
        /// Malformed input: {0} is an invalid input length.
        /// </summary>
        internal static readonly string MalformedInput = "Malformed input: {0} is an invalid input length.";

        /// <summary>
        /// Invalid input, that doesn't conform a base64 string.
        /// </summary>
        internal static readonly string InvalidInput = "The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.";

        /// <summary>
        /// Destination buffer is too small.
        /// </summary>
        internal static readonly string DestinationTooSmall = "The destination buffer is too small.";

        /// <summary>
        /// Invalid {0}, {1} or {2} length.
        /// </summary>
        internal static string FormatInvalidCountOffsetOrLength(object p0, object p1, object p2)
        {
            return string.Format(CultureInfo.CurrentCulture, InvalidCountOffsetOrLength, p0, p1, p2);
        }

        /// <summary>
        /// Malformed input: {0} is an invalid input length.
        /// </summary>
        internal static string FormatMalformedInput(int p0)
        {
            return string.Format(CultureInfo.CurrentCulture, MalformedInput, p0);
        }
    }
}