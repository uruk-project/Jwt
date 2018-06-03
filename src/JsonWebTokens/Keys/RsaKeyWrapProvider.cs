using System;
using System.Security.Cryptography;

namespace JsonWebTokens
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
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// </summary>
        public RsaKeyWrapProvider(RsaJwk key, string algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (!key.IsSupportedAlgorithm(algorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
            }

            Algorithm = algorithm;
            Key = key;
            _rsa = ResolveRsaAlgorithm(key, algorithm);
            _padding = ResolvePadding(algorithm);
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

        private static RSAEncryptionPadding ResolvePadding(string algorithm)
        {
            switch (algorithm)
            {
                case KeyManagementAlgorithms.RsaOaep:
                    return RSAEncryptionPadding.OaepSHA1;
                case KeyManagementAlgorithms.RsaOaep256:
                    return RSAEncryptionPadding.OaepSHA256;
                case KeyManagementAlgorithms.RsaPkcs1:
                    return RSAEncryptionPadding.Pkcs1;
            }

            throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
        }

        /// <summary>
        /// Unwrap a key using RSA decryption.
        /// </summary>
        /// <param name="keyBytes">the bytes to unwrap.</param>
        /// <returns>Unwrapped key</returns>
        public override bool UnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, out int bytesWritten)
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
            catch (Exception ex)
            {
                throw new JsonWebTokenKeyWrapException(ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapFailed), ex);
            }
        }

        /// <summary>
        /// Wrap a key using RSA encryption.
        /// </summary>
        /// <param name="keyBytes">the key to be wrapped</param>
        /// <returns>A wrapped key</returns>
        public override bool WrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, out int bytesWritten)
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
                 return _rsa.TryEncrypt(keyBytes, destination, _padding, out bytesWritten);
#else
                var result = _rsa.Encrypt(keyBytes.ToArray(), _padding);
                bytesWritten = result.Length;
                result.CopyTo(destination);
                return true;
#endif
            }
            catch (Exception ex)
            {
                throw new JsonWebTokenKeyWrapException(ErrorMessages.FormatInvariant(ErrorMessages.KeyWrapFailed), ex);
            }
        }

        private static RSA ResolveRsaAlgorithm(RsaJwk key, string algorithm)
        {
            RSAParameters parameters = key.CreateRsaParameters();
            var rsa = RSA.Create();
            if (rsa != null)
            {
                rsa.ImportParameters(parameters);
            }

            return rsa;
        }

        public override int GetKeyUnwrapSize(int inputSize)
        {
            return inputSize >> 3;
        }

        public override int GetKeyWrapSize(string encryptionAlgorithm)
        {
            return Key.KeySize >> 3;
        }
    }
}
