// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_AESGCM
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace JsonWebToken.Cryptography
{
    internal sealed class AesGcmKeyWrapper : KeyWrapper
    {
        private const int IVSize = 12;
        private const int TagSize = 16;
        private const int IVB64Size = 16;
        private const int TagB64Size = 22;
        private readonly SymmetricJwk _key;

        public AesGcmKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(encryptionAlgorithm, algorithm)
        {
            Debug.Assert(key.SupportKeyManagement(algorithm));
            Debug.Assert(algorithm.Category == AlgorithmCategory.AesGcm);
            _key = key;
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
            => GetKeyWrapSize(EncryptionAlgorithm);

        public static int GetKeyWrapSize(EncryptionAlgorithm encryptionAlgorithm)
            => encryptionAlgorithm.RequiredKeySizeInBytes;

        /// <inheritsdoc />
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
        {
            var cek = CreateSymmetricKey(EncryptionAlgorithm, (SymmetricJwk?)staticKey);
            Span<byte> nonce = stackalloc byte[IVSize];
            RandomNumberGenerator.Fill(nonce);

            Span<byte> tag = stackalloc byte[TagSize];
#if NET8_0_OR_GREATER
            using var aesGcm = new AesGcm(_key.K, TagSize);
#else
            using var aesGcm = new AesGcm(_key.K);
#endif
            var keyBytes = cek.AsSpan();
            if (destination.Length > keyBytes.Length)
            {
                destination = destination.Slice(0, keyBytes.Length);
            }

            aesGcm.Encrypt(nonce, keyBytes, destination, tag);

            Span<byte> nonceB64 = stackalloc byte[IVB64Size];
            Base64Url.Encode(nonce, nonceB64);
            header.Add(JwtHeaderParameterNames.IV, Utf8.GetString(nonceB64));

            Span<byte> tagB64 = stackalloc byte[TagB64Size];
            Base64Url.Encode(tag, tagB64);
            header.Add(JwtHeaderParameterNames.Tag, Utf8.GetString(tagB64));

            return cek;
        }

        /// <inheritsdoc />
        protected override void Dispose(bool disposing)
        {
        }
    }
}
#endif