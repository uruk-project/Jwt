// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Cryptography;

namespace JsonWebToken
{
    /// <summary>Represents a passphrase JSON Web Key.</summary>
    /// <remarks>This JWK is compatible with PBES2 algorithms only.</remarks>
    public sealed class PasswordBasedJwk : Jwk
    {
        private static readonly SaltGenerator _saltGenerator = new SaltGenerator();
        private readonly SymmetricJwk _inner;
        private readonly uint _iterationCount;
        private readonly uint _saltSizeInBytes;

        private PasswordBasedJwk(SymmetricJwk key, uint iterationCount, uint saltSizeInBytes)
        {
            Debug.Assert(key != null);
            _inner = key;
            _iterationCount = iterationCount;
            _saltSizeInBytes = saltSizeInBytes;
            Kid = key.Kid;
        }
        private PasswordBasedJwk(SymmetricJwk key, uint iterationCount, uint saltSizeInBytes, KeyManagementAlgorithm algorithm)
            : base(algorithm)
        {
            Debug.Assert(key != null);
            Debug.Assert(algorithm != null);
            _inner = key;
            _iterationCount = iterationCount;
            _saltSizeInBytes = saltSizeInBytes;
            Kid = key.Kid;
        }

        /// <inheritsdoc />
        public override JsonEncodedText Kty => _inner.Kty;

        /// <inheritsdoc />
        public override int KeySizeInBits => _inner.KeySizeInBits;

        internal byte[] ToArray()
            => _inner.ToArray();

        /// <summary>Returns a new instance of <see cref="PasswordBasedJwk"/>.</summary>
        /// <remarks>The passphrase should not be longer that 128 bytes, and at least 16 bytes for "PBES2-HS256+A128KW", 
        /// 24 bytes for "PBES2-HS384+A192KW" and 32 bytes for "PBES2-HS512+A256KW". The salt size should be at least 8 bytes.</remarks>
        /// <param name="passphrase">The passphrase used for the key derivation. 
        /// This should not be longer that 128 bytes, and at least 16 bytes for "PBES2-HS256+A128KW", 
        /// 24 bytes for "PBES2-HS384+A192KW" and 32 bytes for "PBES2-HS512+A256KW"</param>
        /// <param name="iterationCount">The number of iterations. Should be at least 1000.</param>
        /// <param name="saltSizeInBytes">The salt size, in bytes. Should be at least 8 bytes.</param>
        /// <param name="computeThumbprint">Defines whether the thubpring should be computed.</param>
        public static PasswordBasedJwk FromPassphrase(string passphrase, uint iterationCount = 1000, uint saltSizeInBytes = 8, bool computeThumbprint = true)
        {
            if (passphrase is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.bytes);
            }

            var innerKey = SymmetricJwk.FromByteArray(Utf8.GetBytes(passphrase), computeThumbprint);
            return new PasswordBasedJwk(innerKey, iterationCount, saltSizeInBytes);
        }

        /// <summary>Returns a new instance of <see cref="PasswordBasedJwk"/>.</summary>
        /// <remarks>The passphrase should not be longer that 128 bytes, and at least 16 bytes for "PBES2-HS256+A128KW", 
        /// 24 bytes for "PBES2-HS384+A192KW" and 32 bytes for "PBES2-HS512+A256KW"</remarks>
        /// <param name="passphrase">The passphrase used for the key derivation. 
        /// This should not be longer that 128 bytes, and at least 16 bytes for "PBES2-HS256+A128KW", 
        /// 24 bytes for "PBES2-HS384+A192KW" and 32 bytes for "PBES2-HS512+A256KW"</param>
        /// <param name="algorithm">The key encryption algorithm. It must be a PBES2 algorithm.</param>
        /// <param name="iterationCount">The number of iterations. Should be at least 1000.</param>
        /// <param name="saltSizeInBytes">The salt size, in bytes. Should be at least 8 bytes.</param>
        /// <param name="computeThumbprint">Defines whether the thubpring should be computed.</param>
        public static PasswordBasedJwk FromPassphrase(string passphrase, KeyManagementAlgorithm algorithm, uint iterationCount = 1000, uint saltSizeInBytes = 8, bool computeThumbprint = true)
        {
            if (passphrase is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.bytes);
            }

            var innerKey = SymmetricJwk.FromByteArray(Utf8.GetBytes(passphrase), algorithm, computeThumbprint);
            return new PasswordBasedJwk(innerKey, iterationCount, saltSizeInBytes, algorithm);
        }

        /// <inheritsdoc />
        public override bool SupportKeyManagement(KeyManagementAlgorithm algorithm)
            => algorithm.Category == AlgorithmCategory.Pbkdf2;

        /// <inheritsdoc />
        public override bool SupportSignature(SignatureAlgorithm algorithm)
            => false;

        /// <inheritsdoc />
        public override bool SupportEncryption(EncryptionAlgorithm algorithm)
            => false;

        /// <inheritdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm)
            => throw ThrowHelper.CreateNotSupportedException_Algorithm(algorithm);

        /// <inheritdoc />
        protected override SignatureVerifier CreateSignatureVerifier(SignatureAlgorithm algorithm)
            => throw ThrowHelper.CreateNotSupportedException_Algorithm(algorithm);

        /// <inheritsdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            => new Pbes2KeyWrapper(this, encryptionAlgorithm, algorithm, _iterationCount, _saltSizeInBytes, _saltGenerator);

        /// <inheritsdoc />
        protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            => new Pbes2KeyUnwrapper(this, encryptionAlgorithm, algorithm);

        /// <inheritdoc />      
        protected internal override void Canonicalize(Span<byte> buffer)
            => _inner.Canonicalize(buffer);

        /// <inheritdoc />      
        protected internal override int GetCanonicalizeSize()
            => _inner.GetCanonicalizeSize();

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> AsSpan()
            => _inner.AsSpan();

        /// <inheritdoc />      
        public override void WriteTo(Utf8JsonWriter writer)
        {
            // update properties before to write to JSON
            _inner.KeyOps.Clear();
            foreach (var item in KeyOps)
            {
                _inner.KeyOps.Add(item);
            }

            _inner.Kid = Kid;
            _inner.Use = Use;
            _inner.X5c.Clear();
            foreach (var item in X5c)
            {
                _inner.X5c.Add(item);
            }

            _inner.X5t = X5t;
            _inner.X5tS256 = X5tS256;
            _inner.X5u = X5u;
            _inner.WriteTo(writer);
        }

        /// <inheritsdoc />
        public override bool Equals(Jwk? other)
        {
            if (ReferenceEquals(this, other))
            {
                return true;
            }

            if (!(other is PasswordBasedJwk key))
            {
                return false;
            }

            if (Kid.EncodedUtf8Bytes.Length != 0 && Kid.Equals(other.Kid))
            {
                return true;
            }

            return _inner.Equals(key._inner);
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            base.Dispose();
            _inner.Dispose();
        }

        internal class SaltGenerator : ISaltGenerator
        {
#if !SUPPORT_SPAN_CRYPTO
            private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();
#endif
            public void Generate(Span<byte> salt)
            {
#if SUPPORT_SPAN_CRYPTO
                RandomNumberGenerator.Fill(salt);
#else
                var temp = new byte[salt.Length];
                _randomNumberGenerator.GetBytes(temp);
                temp.CopyTo(salt);
#endif            
            }
        }
    }
}
