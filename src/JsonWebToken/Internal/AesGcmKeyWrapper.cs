// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.
#if NETCOREAPP3_0
using System;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    internal sealed class DirectKeyWrapper : KeyWrapper
    {
        public DirectKeyWrapper(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
        }

        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            return wrappedKeySize;
        }

        public override int GetKeyWrapSize()
        {
            throw new NotImplementedException();
        }

        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            keyBytes.CopyTo(destination);
            bytesWritten = keyBytes.Length;
            return true;
        }

        public override bool TryWrapKey(Jwk staticKey, JwtObject header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten)
        {
            if (staticKey != null)
            {
                throw new NotSupportedException();
            }

            ReadOnlySpan<byte> bytes = Key.AsSpan();
            contentEncryptionKey = SymmetricJwk.FromSpan(bytes, false);

            bytesWritten = bytes.Length;
            return true;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }

    internal sealed class AesGcmKeyWrapper : KeyWrapper
    {
        private const int IVSize = 12;
        private const int TagSize = 16;

        private bool _disposed;

        public AesGcmKeyWrapper(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
            if (algorithm.Category != AlgorithmCategory.AesGcm)
            {
                Errors.ThrowNotSupportedAlgorithmForKeyWrap(algorithm);
            }
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            return wrappedKeySize;
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
        {
            return Key.KeySizeInBits >> 3;
        }

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            Span<byte> nonce = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.IV.Length)];
            Span<byte> tag = stackalloc byte[Base64Url.GetArraySizeRequiredToDecode(header.Tag.Length)];
            try
            {
                Base64Url.Decode(header.IV, nonce);
                Base64Url.Decode(header.Tag, tag);
                using (var aesGcm = new AesGcm(Key.AsSpan()))
                {
                    aesGcm.Decrypt(nonce, keyBytes, tag, destination);
                    bytesWritten = destination.Length;

                    return true;
                }
            }
            catch
            {
                return Errors.TryWriteError(out bytesWritten);
            }
        }

        /// <inheritsdoc />
        public override bool TryWrapKey(Jwk staticKey, JwtObject header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            contentEncryptionKey = SymmetricKeyHelper.CreateSymmetricKey(EncryptionAlgorithm, staticKey);
            Span<byte> nonce = stackalloc byte[IVSize];
            Span<byte> tag = stackalloc byte[TagSize];

            try
            {
                using (var aesGcm = new AesGcm(Key.AsSpan()))
                {
                    aesGcm.Encrypt(nonce, contentEncryptionKey.AsSpan(), destination, tag);
                    bytesWritten = destination.Length;

                    header.Add(new JwtProperty(HeaderParameters.IVUtf8, Base64Url.Encode(nonce)));
                    header.Add(new JwtProperty(HeaderParameters.TagUtf8, Base64Url.Encode(tag)));

                    return true;
                }
            }
            catch
            {
                contentEncryptionKey = null;
                return Errors.TryWriteError(out bytesWritten);
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