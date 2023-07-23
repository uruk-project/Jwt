// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE_KEYWRAPPING
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    internal sealed class EcdhKeyWrapper : KeyWrapper
    {
        private static readonly byte[] _secretPreprend = { 0x0, 0x0, 0x0, 0x1 };

        private readonly IAlgorithm _algorithm;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly HashAlgorithmName _hashAlgorithm;

        private bool _disposed;

        public EcdhKeyWrapper(ECJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
            : base(key, encryptionAlgorithm, contentEncryptionAlgorithm)
        {
            if (contentEncryptionAlgorithm.WrappedAlgorithm is null)
            {
                _algorithm = encryptionAlgorithm;
                _keySizeInBytes = encryptionAlgorithm.RequiredKeySizeInBytes;
            }
            else
            {
                _algorithm = contentEncryptionAlgorithm;
                _keySizeInBytes = contentEncryptionAlgorithm.WrappedAlgorithm.RequiredKeySizeInBits >> 3;
            }

            _algorithmNameLength = _algorithm.Utf8Name.Length;
            _hashAlgorithm = GetHashAlgorithm(encryptionAlgorithm);
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
        {
            int size;
            var alg = Algorithm;
            if (alg.ProduceEncryptionKey)
            {
                var wrappedAlgorithm = alg.WrappedAlgorithm;
                if (wrappedAlgorithm is null)
                {
                    ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(EncryptionAlgorithm);
                }

                size = wrappedAlgorithm.Category switch
                {
                    AlgorithmCategory.Aes => AesKeyWrapper.GetKeyWrappedSize(EncryptionAlgorithm),
#if SUPPORT_AES_GCM
                    AlgorithmCategory.AesGcm => AesGcmKeyWrapper.GetKeyWrapSize(EncryptionAlgorithm),
#endif
                    _ => throw ThrowHelper.CreateNotSupportedException_EncryptionAlgorithm(EncryptionAlgorithm)
                };
            }
            else
            {
                // https://datatracker.ietf.org/doc/html/rfc7516#section-5.2
                if ((alg.Category & AlgorithmCategory.Direct) == AlgorithmCategory.Direct)
                {
                    size = 0;
                }
                else
                {
#if SUPPORT_AES_GCM
                    if (EncryptionAlgorithm.Category == EncryptionType.AesGcm)
                    {
                        size = _keySizeInBytes + 8;
                    }
#endif
                    size = EncryptionAlgorithm.KeyWrappedSizeInBytes;
                }
            }

            return size;
        }

        /// <inheritsdoc />
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtObject header, Span<byte> destination)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var partyUInfo = GetPartyInfo(header, HeaderParameters.ApuUtf8);
            var partyVInfo = GetPartyInfo(header, HeaderParameters.ApvUtf8);
            var secretAppend = BuildSecretAppend(partyUInfo, partyVInfo);
            byte[] exchangeHash;
            var keyParameters = ((ECJwk)Key).ExportParameters();
            using (var otherPartyKey = ECDiffieHellman.Create(keyParameters))
            using (var ephemeralKey = (staticKey is null) ? ECDiffieHellman.Create(keyParameters.Curve) : ECDiffieHellman.Create(((ECJwk)staticKey).ExportParameters(true)))
            {
                exchangeHash = ephemeralKey.DeriveKeyFromHash(otherPartyKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);
                using var epk = ECJwk.FromParameters(ephemeralKey.ExportParameters(false));
                header.Add(new JwtProperty(HeaderParameters.EpkUtf8, epk.AsJwtObject()));
            }

            SymmetricJwk? kek = null;
            SymmetricJwk? contentEncryptionKey;
            try
            {
                kek = SymmetricJwk.FromSpan(new ReadOnlySpan<byte>(exchangeHash, 0, _keySizeInBytes), false);
                if (Algorithm.ProduceEncryptionKey)
                {
                    if (kek.TryGetKeyWrapper(EncryptionAlgorithm, Algorithm.WrappedAlgorithm, out var keyWrapper))
                    {
                        contentEncryptionKey = keyWrapper.WrapKey(null, header, destination);
                    }
                    else
                    {
                        ThrowHelper.ThrowNotSupportedException_AlgorithmForKeyWrap(Algorithm.WrappedAlgorithm);
                        return SymmetricJwk.Empty;
                    }
                }
                else
                {
                    contentEncryptionKey = kek;
                }

                kek = null;
            }
            finally
            {
                if (kek != null)
                {
                    kek.Dispose();
                }
            }

            return contentEncryptionKey;
        }

        protected override void Dispose(bool disposing)
        {
            _disposed = true;
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

        private static byte[]? GetPartyInfo(JwtObject header, ReadOnlySpan<byte> utf8Name)
        {
            if (header.TryGetValue(utf8Name, out var token))
            {
                return (byte[]?)token.Value;
            }

            return null;
        }

        private static void WritePartyInfo(byte[]? partyInfo, int partyInfoLength, Span<byte> destination)
        {
            if (partyInfoLength == 0)
            {
                BinaryPrimitives.WriteInt32BigEndian(destination, 0);
            }
            else
            {
                BinaryPrimitives.WriteInt32BigEndian(destination, partyInfoLength);
                Base64Url.Decode(partyInfo, destination.Slice(sizeof(int)));
            }
        }

        private void WriteAlgorithmId(Span<byte> destination)
        {
            BinaryPrimitives.WriteInt32BigEndian(destination, _algorithmNameLength);
            _algorithm.Utf8Name.CopyTo(destination.Slice(sizeof(int)));
        }

        private byte[] BuildSecretAppend(byte[]? apu, byte[]? apv)
        {
            int apuLength = apu == null ? 0 : Base64Url.GetArraySizeRequiredToDecode(apu.Length);
            int apvLength = apv == null ? 0 : Base64Url.GetArraySizeRequiredToDecode(apv.Length);

            int algorithmLength = sizeof(int) + _algorithmNameLength;
            int partyUInfoLength = sizeof(int) + apuLength;
            int partyVInfoLength = sizeof(int) + apvLength;
            const int suppPubInfoLength = sizeof(int);

            int secretAppendLength = algorithmLength + partyUInfoLength + partyVInfoLength + suppPubInfoLength;
            var secretAppend = new byte[secretAppendLength];
            var secretAppendSpan = secretAppend.AsSpan();
            WriteAlgorithmId(secretAppendSpan);
            secretAppendSpan = secretAppendSpan.Slice(algorithmLength);
            WritePartyInfo(apu, apuLength, secretAppendSpan);
            secretAppendSpan = secretAppendSpan.Slice(partyUInfoLength);
            WritePartyInfo(apv, apvLength, secretAppendSpan);
            secretAppendSpan = secretAppendSpan.Slice(partyVInfoLength);
            BinaryPrimitives.WriteInt32BigEndian(secretAppendSpan, _keySizeInBytes << 3);

            return secretAppend;
        }
    }
}
#endif
