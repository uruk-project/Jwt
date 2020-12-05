// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace JsonWebToken.Cryptography
{
    internal sealed class Pbes2KeyWrapper : KeyWrapper
    {
        private const int IterationCount = 4096;

        private readonly JsonEncodedText _algorithm;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly Sha2 _hashAlgorithm;
        private readonly KeyManagementAlgorithm _keyManagementAlgorithm;
        private readonly byte[] _password;
        private readonly ISaltGenerator _saltGenerator;

        public Pbes2KeyWrapper(PasswordBasedJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm, ISaltGenerator saltGenerator)
            : base(encryptionAlgorithm, algorithm)
        {
            Debug.Assert(key.SupportKeyManagement(algorithm));
            Debug.Assert(algorithm.Category == AlgorithmCategory.Pbkdf2);
            Debug.Assert(algorithm.WrappedAlgorithm != null);
            Debug.Assert(algorithm.HashAlgorithm != null);

            _algorithm = algorithm.Name;
            _keySizeInBytes = algorithm.WrappedAlgorithm.RequiredKeySizeInBits >> 3;
            _algorithmNameLength = _algorithm.EncodedUtf8Bytes.Length;
            _hashAlgorithm = algorithm.HashAlgorithm;
            _keyManagementAlgorithm = algorithm.WrappedAlgorithm;
            _password = key.ToArray();
            _saltGenerator = saltGenerator;
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
        {
            Debug.Assert(Algorithm != null);
            Debug.Assert(Algorithm.WrappedAlgorithm != null);
            Debug.Assert(Algorithm.WrappedAlgorithm.Category == AlgorithmCategory.Aes);
            return AesKeyWrapper.GetKeyWrappedSize(EncryptionAlgorithm);
        }

        /// <inheritsdoc />
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            var contentEncryptionKey = CreateSymmetricKey(EncryptionAlgorithm, (SymmetricJwk?)staticKey);
            Span<byte> salt = stackalloc byte[16 + 1 + _algorithmNameLength];
            _saltGenerator.Generate(salt.Slice(_algorithmNameLength + 1));
            salt[_algorithmNameLength] = 0x00;
            _algorithm.EncodedUtf8Bytes.CopyTo(salt);

            Span<byte> derivedKey = stackalloc byte[_keySizeInBytes];
            Pbkdf2.DeriveKey(_password, salt, _hashAlgorithm, IterationCount, derivedKey);

            header.Add(JwtHeaderParameterNames.P2s, Utf8.GetString(Base64Url.Encode(salt.Slice(_algorithmNameLength + 1, 16))));
            header.Add(JwtHeaderParameterNames.P2c, IterationCount);

            using var keyWrapper = new AesKeyWrapper(derivedKey, EncryptionAlgorithm, _keyManagementAlgorithm);
            return keyWrapper.WrapKey(contentEncryptionKey, header, destination);
        }

        private static HashAlgorithmName GetHashAlgorithm(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.SignatureAlgorithm is null)
            {
                goto Sha256;
            }

            var hashAlgorithm = encryptionAlgorithm.SignatureAlgorithm.HashAlgorithm;
            if (hashAlgorithm == default)
            {
                goto Sha256;
            }

            return hashAlgorithm;

        Sha256:
            return HashAlgorithmName.SHA256;
        }
        protected override void Dispose(bool disposing)
        {
        }
    }
}
