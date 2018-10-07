using System;
using System.Buffers;
using System.Text;

namespace JsonWebToken
{
    public static class Base64UrlExtensions
    {
        public static OperationStatus EncodeToUtf8(this IBase64Url encoder, ReadOnlySpan<char> data, Span<byte> encoded, out int bytesConsumed, out int bytesWritten)
        {
            char[] arrayToReturn = null;
            try
            {
                var utf8data = data.Length > Constants.MaxStackallocBytes
                    ? ArrayPool<char>.Shared.Rent(data.Length).AsSpan(0, data.Length)
                    : stackalloc char[data.Length];
                return encoder.EncodeToUtf8(utf8data, encoded, out bytesConsumed, out bytesWritten);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<char>.Shared.Return(arrayToReturn);
                }
            }
        }

        public static string EncodeToUtf8(this IBase64Url encoder, ReadOnlySpan<byte> data)
        {
            byte[] arrayToReturn = null;
            int base64UrlLength = encoder.GetMaxEncodedToUtf8Length(data.Length);
            try
            {
                var utf8Encoded = base64UrlLength > Constants.MaxStackallocBytes
                    ? ArrayPool<byte>.Shared.Rent(base64UrlLength).AsSpan(0, base64UrlLength)
                    : stackalloc byte[base64UrlLength];

                encoder.EncodeToUtf8(data, utf8Encoded, out var bytesConsumed, out var bytesWritten);
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

        public static string EncodeToUtf8(this IBase64Url encoder, string data)
        {
            byte[] arrayToReturn = null;
            int base64UrlLength = encoder.GetMaxEncodedToUtf8Length(data.Length);
            try
            {
                var utf8Encoded = base64UrlLength > Constants.MaxStackallocBytes
                    ? ArrayPool<byte>.Shared.Rent(base64UrlLength).AsSpan(0, base64UrlLength)
                    : stackalloc byte[base64UrlLength];

#if NETCOREAPP2_1
                encoder.EncodeToUtf8(data, utf8Encoded, out var bytesConsumed, out var bytesWritten);
                return Encoding.UTF8.GetString(utf8Encoded);
#else
                encoder.EncodeToUtf8(data.AsSpan(), utf8Encoded, out var bytesConsumed, out var bytesWritten);
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
    }
}