// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE_SIGNATURE
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class EcdsaSignatureVerifier : SignatureVerifier
    {
        private readonly ObjectPool<ECDsa> _ecdsaPool;
        private readonly int _hashSize;
        private readonly Sha2 _sha;
        private readonly int _base64HashSize;
        private bool _disposed;

        public EcdsaSignatureVerifier(ECJwk key, SignatureAlgorithm algorithm)
            : base(algorithm)
        {
            Debug.Assert(key != null);
            Debug.Assert(key.KeySizeInBits == algorithm.RequiredKeySizeInBits);

            _sha = algorithm.Sha;
            _hashSize = key.Crv.HashSize;
            _base64HashSize = Base64Url.GetArraySizeRequiredToEncode(_hashSize);

            _ecdsaPool = new ObjectPool<ECDsa>(new ECDsaObjectPoolPolicy(key, algorithm));
        }

        /// <inheritsdoc />
        public override int HashSizeInBytes => _hashSize;

        public override int Base64HashSizeInBytes => _base64HashSize;

        /// <inheritsdoc />
        public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            Debug.Assert(!_disposed);
            if (data.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.data);
            }

            if (signature.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.signature);
            }

            var ecdsa = _ecdsaPool.Get();
#if SUPPORT_SPAN_CRYPTO
            Span<byte> hash = stackalloc byte[Sha2.BlockSizeStackallocThreshold].Slice(0, _sha.HashSize);
            _sha.ComputeHash(data, hash);
            return ecdsa.VerifyHash(hash, signature);
#else
            byte[] hash = new byte[_sha.HashSize];
            _sha.ComputeHash(data, hash);
            return ecdsa.VerifyHash(hash, signature.ToArray());
#endif
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _ecdsaPool.Dispose();
                }

                _disposed = true;
            }
        }
    }
}
#endif