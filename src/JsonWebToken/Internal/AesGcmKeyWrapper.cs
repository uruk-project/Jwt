using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken.Internal
{
    public sealed class AesGcmKeyWrapper : KeyWrapper
    {
        private const int IVSize = 12;
        private const int TagSize = 16;

        private bool _disposed;

        public AesGcmKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            if (key.K == null)
            {
                Errors.ThrowMalformedKey(key);
            }
        }

        public override int GetKeyUnwrapSize(int inputSize)
        {
            return GetKeyUnwrappedSize(inputSize, Algorithm);
        }

        public override int GetKeyWrapSize()
        {
            return GetKeyWrappedSize(EncryptionAlgorithm);
        }

        public static int GetKeyUnwrappedSize(int inputSize, KeyManagementAlgorithm algorithm)
        {
            return inputSize - 8;
        }

        public static int GetKeyWrappedSize(EncryptionAlgorithm encryptionAlgorithm)
        {
            return encryptionAlgorithm.RequiredKeyWrappedSizeInBytes;
        }

        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            Span<byte> nonce = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.IV.Length)];
            Span<byte> tag = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.Tag.Length)];
            Base64Url.Base64UrlDecode(header.IV, nonce);
            Base64Url.Base64UrlDecode(header.Tag, tag);
            using (var aesGcm = new AesGcm(Key.ToByteArray()))
            {
                aesGcm.Decrypt(nonce, keyBytes, tag, destination);
                bytesWritten = destination.Length;

                return true;
            }
        }

        public override bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            contentEncryptionKey = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
            Span<byte> nonce = stackalloc byte[IVSize];
            Span<byte> tag = stackalloc byte[TagSize];
            using (var aesGcm = new AesGcm(Key.ToByteArray()))
            {
                aesGcm.Encrypt(nonce, contentEncryptionKey.ToByteArray(), destination, tag);
                bytesWritten = destination.Length;

                header.Add(HeaderParameters.IV, Base64Url.Base64UrlEncode(nonce));
                header.Add(HeaderParameters.Tag, Base64Url.Base64UrlEncode(tag));

                return true;
            }
        }

        protected override void Dispose(bool disposing)
        {
            _disposed = true;
        }
    }
}
