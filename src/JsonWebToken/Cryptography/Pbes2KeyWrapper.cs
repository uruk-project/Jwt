// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace JsonWebToken.Cryptography
{
    internal sealed class Pbes2KeyWrapper : KeyWrapper
    {
        private const int KeySizeThreshold = 32;

        private readonly JsonEncodedText _algorithm;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly Sha2 _hashAlgorithm;
        private readonly KeyManagementAlgorithm _keyManagementAlgorithm;
        private readonly byte[] _password;
        private readonly uint _iterationCount;
        private readonly int _saltSizeInBytes;
        private readonly ISaltGenerator _saltGenerator;

        public Pbes2KeyWrapper(PasswordBasedJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm, uint iterationCount, uint saltSizeInBytes, ISaltGenerator saltGenerator)
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
            _iterationCount = iterationCount;
            _saltSizeInBytes = (int)saltSizeInBytes;
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
            int bufferSize = _saltSizeInBytes + _algorithmNameLength + 1;
            byte[]? bufferToReturn = null;
            Span<byte> buffer = bufferSize > Pbkdf2.SaltSizeThreshold + 18 + 1  // 18 = max alg name length
              ? (bufferToReturn = ArrayPool<byte>.Shared.Rent(bufferSize))
              : stackalloc byte[Pbkdf2.SaltSizeThreshold + 18 + 1];
            buffer = buffer.Slice(0, bufferSize);
            _saltGenerator.Generate(buffer.Slice(_algorithmNameLength + 1));
            buffer[_algorithmNameLength] = 0x00;
            _algorithm.EncodedUtf8Bytes.CopyTo(buffer);

            Span<byte> derivedKey = stackalloc byte[KeySizeThreshold].Slice(0, _keySizeInBytes);
            Pbkdf2.DeriveKey(_password, buffer, _hashAlgorithm, _iterationCount, derivedKey);

            Span<byte> salt = buffer.Slice(_algorithmNameLength + 1, _saltSizeInBytes);
            int saltLengthB64 = Base64Url.GetArraySizeRequiredToEncode(salt.Length);
            byte[]? arrayToReturn = null;
            Span<byte> b64Salt = saltLengthB64 > Pbkdf2.SaltSizeThreshold * 4 / 3
                ? (arrayToReturn = ArrayPool<byte>.Shared.Rent(saltLengthB64))
                : stackalloc byte[Pbkdf2.SaltSizeThreshold * 4 / 3];
            try
            {
                int length = Base64Url.Encode(salt, b64Salt);
                header.Add(JwtHeaderParameterNames.P2s, Utf8.GetString(b64Salt.Slice(0, saltLengthB64)));
                header.Add(JwtHeaderParameterNames.P2c, _iterationCount);

                using var keyWrapper = new AesKeyWrapper(derivedKey, EncryptionAlgorithm, _keyManagementAlgorithm);
                return keyWrapper.WrapKey(contentEncryptionKey, header, destination);
            }
            finally
            {
                if (bufferToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(bufferToReturn);
                }

                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }
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
        protected override void Dispose(bool disposing)
        {
        }
    }
}
