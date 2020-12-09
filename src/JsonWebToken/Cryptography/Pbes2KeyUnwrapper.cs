// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace JsonWebToken.Cryptography
{
    internal sealed class Pbes2KeyUnwrapper : KeyUnwrapper
    {
        private readonly JsonEncodedText _algorithm;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly Sha2 _hashAlgorithm;
        private readonly KeyManagementAlgorithm _keyManagementAlgorithm;
        private readonly byte[] _password;

        internal Pbes2KeyUnwrapper(PasswordBasedJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
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
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int inputSize)
            => EncryptionAlgorithm.RequiredKeySizeInBytes;

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeaderDocument header, out int bytesWritten)
        {
            if (!header.TryGetHeaderParameter(JwtHeaderParameterNames.P2c.EncodedUtf8Bytes, out JwtElement p2c))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(JwtHeaderParameterNames.P2c);
            }

            if (!header.TryGetHeaderParameter(JwtHeaderParameterNames.P2s.EncodedUtf8Bytes, out JwtElement p2s))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(JwtHeaderParameterNames.P2s);
            }

            int iterationCount = (int)p2c.GetInt64();
            var b64p2s = p2s.GetRawValue();
            int p2sLength = Base64Url.GetArraySizeRequiredToDecode(b64p2s.Length);


            Span<byte> salt = stackalloc byte[p2sLength + 1 + _algorithmNameLength];
            Base64Url.Decode(b64p2s.Span, salt.Slice(_algorithmNameLength + 1));
            salt[_algorithmNameLength] = 0x00;
            _algorithm.EncodedUtf8Bytes.CopyTo(salt);

            Span<byte> derivedKey = stackalloc byte[_keySizeInBytes];
            Pbkdf2.DeriveKey(_password, salt, _hashAlgorithm, (uint)iterationCount, derivedKey);

            using var keyUnwrapper = new AesKeyUnwrapper(derivedKey, EncryptionAlgorithm, _keyManagementAlgorithm);
            return keyUnwrapper.TryUnwrapKey(keyBytes, destination, header, out bytesWritten);
        }

        protected override void Dispose(bool disposing)
        {
        }

        private static HashAlgorithmName GetHashAlgorithm(EncryptionAlgorithm encryptionAlgorithm)
        {
            Debug.Assert(encryptionAlgorithm.SignatureAlgorithm != null);
            var hashAlgorithm = encryptionAlgorithm.SignatureAlgorithm.HashAlgorithm;
            if (hashAlgorithm == default)
            {
                goto Sha256;
            }

            return hashAlgorithm;

        Sha256:
            return HashAlgorithmName.SHA256;
        }
    }
}
