// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Text.Json;

namespace JsonWebToken
{
    internal class NoneSigner : Signer
    {
        public static NoneSigner Default = new NoneSigner(NullJwk.Default, SignatureAlgorithm.None);

        public NoneSigner(Jwk key, SignatureAlgorithm algorithm)
            : base(key, algorithm)
        {
        }

        public override int HashSizeInBytes => 0;

        public override bool TrySign(ReadOnlySpan<byte> input, Span<byte> destination, out int bytesWritten)
        {
            bytesWritten = 0;
            return true;
        }

        public override bool Verify(ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
        }

        private class NullJwk : Jwk
        {
            public static readonly NullJwk Default = new NullJwk();

            public override ReadOnlySpan<byte> Kty => throw new NotImplementedException();

            public override int KeySizeInBits => throw new NotImplementedException();

            public override ReadOnlySpan<byte> AsSpan()
            {
                throw new NotImplementedException();
            }

            public override byte[] Canonicalize()
            {
                throw new NotImplementedException();
            }

            public override AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
            {
                throw new NotImplementedException();
            }

            public override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            {
                throw new NotImplementedException();
            }

            public override Signer CreateSignerForSignature(SignatureAlgorithm algorithm)
            {
                throw new NotImplementedException();
            }

            public override Signer CreateSignerForValidation(SignatureAlgorithm algorithm)
            {
                throw new NotImplementedException();
            }

            public override bool Equals(Jwk other)
            {
                throw new NotImplementedException();
            }

            public override bool IsSupported(SignatureAlgorithm algorithm)
            {
                throw new NotImplementedException();
            }

            public override bool IsSupported(KeyManagementAlgorithm algorithm)
            {
                throw new NotImplementedException();
            }

            public override bool IsSupported(EncryptionAlgorithm algorithm)
            {
                throw new NotImplementedException();
            }

            internal override void WriteComplementTo(ref Utf8JsonWriter writer)
            {
                throw new NotImplementedException();
            }
        }
    }
}
