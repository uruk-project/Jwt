﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_AESGCM
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class AesGcmKeyUnwrapper : KeyUnwrapper
    {
        private const int IVSize = 12;
        private const int TagSize = 16;

        private readonly SymmetricJwk _key;

        public AesGcmKeyUnwrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(encryptionAlgorithm, algorithm)
        {
            Debug.Assert(key.SupportKeyManagement(algorithm));
            Debug.Assert(algorithm.Category == AlgorithmCategory.AesGcm);
            _key = key;
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int wrappedKeySize)
            => wrappedKeySize;

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeaderDocument header, out int bytesWritten)
        {
            if (!header.TryGetHeaderParameter(JwtHeaderParameterNames.IV.EncodedUtf8Bytes,out var encodedIV))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(JwtHeaderParameterNames.IV);
            }

            if (!header.TryGetHeaderParameter(JwtHeaderParameterNames.Tag.EncodedUtf8Bytes, out var encodedTag))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(JwtHeaderParameterNames.Tag);
            }

            var rawIV = encodedIV.GetRawValue();
            Span<byte> nonce = stackalloc byte[IVSize];
            var rawTag = encodedTag.GetRawValue();
            Span<byte> tag = stackalloc byte[TagSize];
            try
            {
                Base64Url.Decode(rawIV.Span, nonce);
                Base64Url.Decode(rawTag.Span, tag);
                using var aesGcm = new AesGcm(_key.K);
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
        }
    }
}
#endif