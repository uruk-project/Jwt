using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    public class AesGcmKeyWrapProvider : KeyWrapProvider
    {
        private const int IVSize = 12;
        private const int TagSize = 16;

        public AesGcmKeyWrapProvider(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (!key.IsSupportedAlgorithm(encryptionAlgorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, encryptionAlgorithm));
            }

            if (!key.IsSupportedAlgorithm(algorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
            }

            if (key.K == null)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.MalformedKey, key.Kid), nameof(key.K));
            }

            Algorithm = algorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
            Key = key;
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

        public override bool TryUnwrapKey(Span<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            byte[] nonce = Base64Url.Base64UrlDecode(header.IV);
            byte[] tag = Base64Url.Base64UrlDecode(header.Tag);

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
            throw new NotImplementedException();
        }
    }
}
