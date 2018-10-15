using JsonWebToken.Internal;
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
        private readonly RSA _rsa;
        private readonly RSAEncryptionPadding _padding;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKeyWrapper"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for crypto operations.</param>
        /// <param name="contentEncryptionAlgorithm">The KeyWrap algorithm to apply.</param>
        /// </summary>
        public RsaKeyWrapper(RsaJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
            : base(key, encryptionAlgorithm, contentEncryptionAlgorithm)
        {
#if NETCOREAPP2_1
            _rsa = RSA.Create(key.ExportParameters());
#else
            _rsa = RSA.Create();
            _rsa.ImportParameters(key.ExportParameters());
#endif

            if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep)
            {
                _padding = RSAEncryptionPadding.OaepSHA1;
            }
            else if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep256
                || contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaPkcs1)
            {
                _padding = RSAEncryptionPadding.OaepSHA256;
            }
            else if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep384)
            {
                _padding = RSAEncryptionPadding.OaepSHA384;
            }
            else if (contentEncryptionAlgorithm == KeyManagementAlgorithm.RsaOaep512)
            {
                _padding = RSAEncryptionPadding.OaepSHA512;
            }
            else
            {
                Errors.ThrowNotSupportedAlgorithmForKeyWrap(contentEncryptionAlgorithm);
            }
        }

        /// <summary>
        /// Unwrap a key using RSA decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (keyBytes.IsEmpty)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
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
                return Errors.TryWriteError(out bytesWritten);
            }
        }

        /// <summary>
        /// Wrap a key using RSA encryption.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>A wrapped key</returns>
        public override bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten)
        {
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
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
                return Errors.TryWriteError(out bytesWritten);
            }
        }

        public override int GetKeyUnwrapSize(int inputSize)
        {
            return EncryptionAlgorithm.RequiredKeySizeInBytes;
        }

        public override int GetKeyWrapSize()
        {
            return Key.KeySizeInBits >> 3;
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
                    _rsa.Dispose();
                }

                _disposed = true;
            }
        }
    }
}
