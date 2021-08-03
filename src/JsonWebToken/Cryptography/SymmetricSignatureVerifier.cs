// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;

namespace JsonWebToken.Cryptography
{
    /// <summary>Provides signature verifying operations using a <see cref="SymmetricJwk"/> and specifying an algorithm.</summary>
    internal sealed class SymmetricSignatureVerifier : SignatureVerifier
    {
        private readonly HmacSha2 _hashAlgorithm;
        private bool _disposed;

        /// <summary>This is the minimum <see cref="SymmetricJwk"/>.KeySize when creating and verifying signatures.</summary>
        public const int DefaultMinimumSymmetricKeySizeInBits = 128;

        private readonly int _hashSizeInBytes;
        private readonly int _base64HashSizeInBytes;
        private int _minimumKeySizeInBits = DefaultMinimumSymmetricKeySizeInBits;

        public SymmetricSignatureVerifier(ReadOnlySpan<byte> key, SignatureAlgorithm algorithm)
            : base(algorithm)
        {
            Debug.Assert(algorithm.Category == AlgorithmCategory.Hmac);

            if (key.Length << 3 < MinimumKeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_AlgorithmRequireMinimumKeySize(key.Length << 3, algorithm.Name.ToString(), MinimumKeySizeInBits);
            }

            _hashSizeInBytes = Algorithm.RequiredKeySizeInBits >> 2;
            _base64HashSizeInBytes = Base64Url.GetArraySizeRequiredToEncode(_hashSizeInBytes);
            _hashAlgorithm = new HmacSha2(algorithm.Sha, key);
        }

        /// <inheritsdoc />
        public override int HashSizeInBytes => _hashSizeInBytes;

        public override int Base64HashSizeInBytes => _base64HashSizeInBytes;

        /// <summary>Gets or sets the minimum <see cref="SymmetricJwk"/>.KeySize.</summary>
        public int MinimumKeySizeInBits
        {
            get
            {
                return _minimumKeySizeInBits;
            }

            set
            {
                if (value < DefaultMinimumSymmetricKeySizeInBits)
                {
                    ThrowHelper.ThrowArgumentOutOfRangeException_MustBeAtLeast(ExceptionArgument.value, DefaultMinimumSymmetricKeySizeInBits);
                }

                _minimumKeySizeInBits = value;
            }
        }

        /// <inheritsdoc />
        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            Debug.Assert(!_disposed);

            Span<byte> hash = stackalloc byte[Sha2.HashSizeStackallocThreshold].Slice(0, _hashSizeInBytes);
            _hashAlgorithm.ComputeHash(input, hash);
            return CryptographicOperations.FixedTimeEquals(signature, hash);
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _hashAlgorithm.Clear();
                }

                _disposed = true;
            }
        }
    }
}
