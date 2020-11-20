// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_AESGCM
using System;
using System.Security.Cryptography;

namespace JsonWebToken
{
    internal sealed class AesGcmKeyUnwrapper : KeyUnwrapper
    {
        private bool _disposed;

        public AesGcmKeyUnwrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            if (algorithm.Category != AlgorithmCategory.AesGcm)
            {
                ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(algorithm);
            }
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            return wrappedKeySize;
        }

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeaderDocument header, out int bytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var encodedIV = header.IV;
            var encodedTag = header.Tag;
            if (encodedIV is null)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(HeaderParameters.IV);
            }

            if (encodedTag is null)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(HeaderParameters.Tag);
            }

            Span<byte> nonce = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(encodedIV.Length)];
            Span<byte> tag = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(encodedTag.Length)];
            try
            {
                Base64Url.Decode(encodedIV, nonce);
                Base64Url.Decode(encodedTag, tag);
                using var aesGcm = new AesGcm(Key.AsSpan());
                if (destination.Length > keyBytes.Length)
                {
                    destination = destination.Slice(0, keyBytes.Length);
                }

                aesGcm.Decrypt(nonce, keyBytes, tag, destination);
                bytesWritten = destination.Length;

                return true;
            }
            catch (CryptographicException)
            {
                return ThrowHelper.TryWriteError(out bytesWritten);
            }
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
            _disposed = true;
        }
    }
}
#endif