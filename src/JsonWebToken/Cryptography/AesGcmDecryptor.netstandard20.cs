// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.
#if NETSTANDARD2_0 || NET461 || NETCOREAPP2_1
using System;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated decryption for AES GCM algorithm.
    /// </summary>
    internal sealed class AesGcmDecryptor : AuthenticatedDecryptor
    {
        public AesGcmDecryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            throw new NotSupportedException();
        }
        
        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
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