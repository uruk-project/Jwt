using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    public sealed class AesGcmKeyWrapper : KeyWrapper
    {
        private const int IVSize = 12;
        private const int TagSize = 16;

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

        public override unsafe bool TryUnwrapKey(Span<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            Span<byte> nonce = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.IV.Length)];
            Span<byte> tag = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.Tag.Length)];
#if NETCOREAPP2_1
            Base64Url.Base64UrlDecode(header.IV, nonce);
            Base64Url.Base64UrlDecode(header.Tag, tag);
#else
            Base64Url.Base64UrlDecode(header.IV.AsSpan(), nonce);
            Base64Url.Base64UrlDecode(header.Tag.AsSpan(), tag);
#endif 
            using (var aesGcm = new AesGcm(Key.ToByteArray()))
            {
                aesGcm.Decrypt(nonce, keyBytes, tag, destination);
                bytesWritten = destination.Length;

                return true;
            }
        }

        public override bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten)
        {
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
        }
    }
}
