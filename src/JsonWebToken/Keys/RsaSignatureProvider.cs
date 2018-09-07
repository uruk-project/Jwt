﻿using JsonWebToken.ObjectPooling;
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public sealed class RsaSignatureProvider : SignatureProvider
    {
        private readonly ObjectPool<RSA> _hashAlgorithmPool;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly int _hashSizeInBytes;
        private readonly RSASignaturePadding _signaturePadding;

        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricSignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="JsonWebKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">Whether this <see cref="AsymmetricSignatureProvider"/> is required to create signatures then set this to true.</param>
        /// <para>
        /// Creating signatures requires that the <see cref="JsonWebKey"/> has access to a private key.
        /// Verifying signatures (the default), does not require access to the private key.
        /// </para>
        public RsaSignatureProvider(RsaJwk key, SignatureAlgorithm algorithm, bool willCreateSignatures)
            : base(key, algorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (willCreateSignatures && !key.HasPrivateKey)
            {
                throw new InvalidOperationException(ErrorMessages.FormatInvariant(ErrorMessages.MissingPrivateKey, key.Kid));
            }

            if (!key.IsSupportedAlgorithm(algorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedSignatureAlgorithm, (algorithm.Name ?? "null"), key));
            }

            var minKeySize = willCreateSignatures ? 2048 : 1024;
            if (key.KeySizeInBits < minKeySize)
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.SigningKeyTooSmall, key.Kid, minKeySize, key.KeySizeInBits));
            }

            _hashAlgorithm = algorithm.HashAlgorithm;
            switch (algorithm.Name)
            {
                case SignatureAlgorithms.RsaSha256:
                case SignatureAlgorithms.RsaSha384:
                case SignatureAlgorithms.RsaSha512:
                    _signaturePadding = RSASignaturePadding.Pkcs1;
                    break;

                case SignatureAlgorithms.RsaSsaPssSha256:
                case SignatureAlgorithms.RsaSsaPssSha384:
                case SignatureAlgorithms.RsaSsaPssSha512:
                    _signaturePadding = RSASignaturePadding.Pss;
                    break;

                default:
                    throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedAlgorithm, algorithm));
            }

            _hashSizeInBytes = key.KeySizeInBits >> 3;
            _hashAlgorithmPool = new ObjectPool<RSA>(new RsaObjectPoolPolicy(key.ExportParameters()));
        }

        public override int HashSizeInBytes => _hashSizeInBytes;

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="AsymmetricJwk"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( JsonWebKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">The bytes to be signed.</param>
        /// <returns>A signature over the input.</returns>
        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            if (input.IsEmpty)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            var rsa = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
                return rsa.TrySignData(input, destination, _hashAlgorithm, _signaturePadding, out bytesWritten);
#else
                try
                {
                    var result = rsa.SignData(input.ToArray(), _hashAlgorithm, _signaturePadding);
                    bytesWritten = result.Length;
                    result.CopyTo(destination);
                    return true;
                }
                catch
                {
                    bytesWritten = 0;
                    return false;
                }
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(rsa);
            }
        }

        /// <summary>
        /// Verifies that a signature over the' input' matches the signature.
        /// </summary>
        /// <param name="input">The bytes to generate the signature over.</param>
        /// <param name="signature">The value to verify against.</param>
        /// <returns>true if signature matches, false otherwise.</returns>
        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            if (input.IsEmpty)
            {
                throw new ArgumentNullException(nameof(input));
            }

            if (signature.IsEmpty)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            var rsa = _hashAlgorithmPool.Get();
            try
            {
#if NETCOREAPP2_1
                return rsa.VerifyData(input, signature, _hashAlgorithm, _signaturePadding);
#else
                return rsa.VerifyData(input.ToArray(), signature.ToArray(), _hashAlgorithm, _signaturePadding);
#endif
            }
            finally
            {
                _hashAlgorithmPool.Return(rsa);
            }
        }

        /// <summary>
        /// Calls <see cref="RSA.Dispose()"/> to release this managed resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _hashAlgorithmPool.Dispose();
                }

                _disposed = true;
            }
        }

        private sealed class RsaObjectPoolPolicy : PooledObjectPolicy<RSA>
        {
            private readonly RSAParameters _parameters;

            public RsaObjectPoolPolicy(RSAParameters parameters)
            {
                _parameters = parameters;
            }

            public override RSA Create()
            {
#if NETCOREAPP2_1
                return RSA.Create(_parameters);
#else
                var rsa = RSA.Create();
                rsa.ImportParameters(_parameters);
                return rsa;
#endif
            }

            public override bool Return(RSA obj)
            {
                return true;
            }
        }
    }
}