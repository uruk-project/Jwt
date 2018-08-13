using Newtonsoft.Json.Linq;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides RSA Wrap key and Unwrap key services.
    /// </summary>
    public class RsaKeyWrapProvider : KeyWrapProvider
    {
        private RSA _rsa;
        private readonly RSAEncryptionPadding _padding;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKeyWrapProvider"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for crypto operations.</param>
        /// <param name="contentEncryptionAlgorithm">The KeyWrap algorithm to apply.</param>
        /// </summary>
        public RsaKeyWrapProvider(RsaJwk key, in EncryptionAlgorithm encryptionAlgorithm, in KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (contentEncryptionAlgorithm == KeyManagementAlgorithm.Empty)
            {
                throw new ArgumentNullException(nameof(contentEncryptionAlgorithm));
            }

            if (encryptionAlgorithm == EncryptionAlgorithm.Empty)
            {
                throw new ArgumentNullException(nameof(encryptionAlgorithm));
            }

            if (!key.IsSupportedAlgorithm(contentEncryptionAlgorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, contentEncryptionAlgorithm));
            }

            Algorithm = contentEncryptionAlgorithm;
            EncryptionAlgorithm = encryptionAlgorithm;
            Key = key;
            _rsa = ResolveRsaAlgorithm(key, contentEncryptionAlgorithm);
            _padding = ResolvePadding(contentEncryptionAlgorithm);
        }

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (_rsa != null)
                    {
                        _rsa.Dispose();
                    }

                    _disposed = true;
                }
            }
        }

        private static RSAEncryptionPadding ResolvePadding(in KeyManagementAlgorithm algorithm)
        {
            switch (algorithm.Id)
            {
                case KeyManagementAlgorithms.RsaOaepId:
                    return RSAEncryptionPadding.OaepSHA1;
                case KeyManagementAlgorithms.RsaOaep256Id:
                    return RSAEncryptionPadding.OaepSHA256;
                case KeyManagementAlgorithms.RsaPkcs1Id:
                    return RSAEncryptionPadding.Pkcs1;
            }

            throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
        }

        /// <summary>
        /// Unwrap a key using RSA decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool TryUnwrapKey(Span<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (_rsa == null)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedUnwrap, Algorithm));
            }

            try
            {
#if NETCOREAPP2_1
                return _rsa.TryDecrypt(keyBytes, destination, _padding, out bytesWritten);
#else
                var result = _rsa.Decrypt(keyBytes.ToArray(), _padding);
                bytesWritten = result.Length;
                result.CopyTo(destination);
                return true;
#endif
            }
            catch
            {
                bytesWritten = 0;
                return false;
            }
        }

        /// <summary>
        /// Wrap a key using RSA encryption.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>A wrapped key</returns>
        public override bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (_rsa == null)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedUnwrap, Algorithm));
            }

            try
            {
                contentEncryptionKey = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
#if NETCOREAPP2_1
                return _rsa.TryEncrypt(contentEncryptionKey.ToByteArray(), destination, _padding, out bytesWritten);
#else
                var result = _rsa.Encrypt(contentEncryptionKey.ToByteArray(), _padding);
                result.CopyTo(destination);
                bytesWritten = result.Length;
                return true;
#endif
            }
            catch
            {
                contentEncryptionKey = null;
                bytesWritten = 0;
                return false;
            }
        }

        private static RSA ResolveRsaAlgorithm(RsaJwk key, in KeyManagementAlgorithm algorithm)
        {
            var rsa = RSA.Create();
            if (rsa != null)
            {
                RSAParameters parameters = key.CreateRsaParameters();
                rsa.ImportParameters(parameters);
            }

            return rsa;
        }

        public override int GetKeyUnwrapSize(int inputSize)
        {
            return EncryptionAlgorithm.RequiredKeySizeInBytes;
        }

        public override int GetKeyWrapSize()
        {
            return Key.KeySizeInBits >> 3;
        }
    }
}
