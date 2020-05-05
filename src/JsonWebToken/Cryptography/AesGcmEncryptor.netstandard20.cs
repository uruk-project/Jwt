// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if NETSTANDARD2_0 || NET461 || NET47 || NETCOREAPP2_1
using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption for AES GCM algorithm.
    /// </summary>
    internal sealed class AesGcmEncryptor : AuthenticatedEncryptor
    {
        public AesGcmEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> authenticationTag)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetCiphertextSize(int plaintextSize)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetNonceSize()
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetBase64NonceSize()
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetTagSize()
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override int GetBase64TagSize()
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public override void Dispose()
        {
        }
    } 
}
#endif