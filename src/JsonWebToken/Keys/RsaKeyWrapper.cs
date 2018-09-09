using Newtonsoft.Json.Linq;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    /// <summary>
    /// Provides RSA Wrap key and Unwrap key services.
    /// </summary>
    public sealed class RsaKeyWrapper : KeyWrapper
    {
        private RSA _rsa;
        private readonly RSAEncryptionPadding _padding;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKeyWrapper"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for crypto operations.</param>
        /// <param name="contentEncryptionAlgorithm">The KeyWrap algorithm to apply.</param>
        /// </summary>
        public RsaKeyWrapper(RsaJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
            : base(key, encryptionAlgorithm, contentEncryptionAlgorithm)
        {
            _rsa = ResolveRsaAlgorithm(key);
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
                }

                _disposed = true;
            }
        }

        private static RSAEncryptionPadding ResolvePadding(KeyManagementAlgorithm algorithm)
        {
            if (algorithm == KeyManagementAlgorithm.RsaOaep)
            {
                return RSAEncryptionPadding.OaepSHA1;
            }
            else if (algorithm == KeyManagementAlgorithm.RsaOaep256)
            {
                return RSAEncryptionPadding.OaepSHA256;
            }
            else if (algorithm == KeyManagementAlgorithm.RsaPkcs1)
            {
                return RSAEncryptionPadding.OaepSHA256;
            }

            throw new NotSupportedException(ErrorMessages.NotSuportedAlgorithmForKeyWrap(algorithm));
        }

        /// <summary>
        /// Unwrap a key using RSA decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool TryUnwrapKey(Span<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (keyBytes.IsEmpty)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (_rsa == null)
            {
                throw new NotSupportedException(ErrorMessages.NotSupportedUnwrap(Algorithm));
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
                throw new NotSupportedException(ErrorMessages.NotSupportedUnwrap(Algorithm));
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

        private static RSA ResolveRsaAlgorithm(RsaJwk key)
        {
#if NETCOREAPP2_1
            return RSA.Create(key.ExportParameters());
#else
            var rsa = RSA.Create();
            rsa.ImportParameters(key.ExportParameters());
            return rsa;
#endif
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
