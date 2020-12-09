// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE_KEYWRAPPING
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace JsonWebToken.Cryptography
{
    internal sealed class EcdhKeyWrapper : KeyWrapper
    {
        private static readonly byte[] _secretPreprend = { 0x0, 0x0, 0x0, 0x1 };

        private readonly JsonEncodedText _algorithm;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly KeyManagementAlgorithm? _keyManagementAlgorithm;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly ECJwk _key;

        public EcdhKeyWrapper(ECJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(encryptionAlgorithm, algorithm)
        {
            Debug.Assert(key.SupportKeyManagement(algorithm));
            Debug.Assert(algorithm.Category == AlgorithmCategory.EllipticCurve);
            _key = key;
            if (algorithm.WrappedAlgorithm is null)
            {
                _algorithm = encryptionAlgorithm.Name;
                _keySizeInBytes = encryptionAlgorithm.RequiredKeySizeInBytes;
            }
            else
            {
                _algorithm = algorithm.Name;
                _keySizeInBytes = algorithm.WrappedAlgorithm.RequiredKeySizeInBits >> 3;
                _keyManagementAlgorithm = algorithm.WrappedAlgorithm;
            }

            _algorithmNameLength = _algorithm.EncodedUtf8Bytes.Length;
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
                if (alg == KeyManagementAlgorithm.EcdhEs)
                {
                    size = _keySizeInBytes;
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
        public override SymmetricJwk WrapKey(Jwk? staticKey, JwtHeader header, Span<byte> destination)
        {
            Debug.Assert(header != null);

            var partyUInfo = GetPartyInfo(header, JwtHeaderParameterNames.Apu);
            var partyVInfo = GetPartyInfo(header, JwtHeaderParameterNames.Apv);
            var secretAppend = BuildSecretAppend(partyUInfo, partyVInfo);
            ReadOnlySpan<byte> exchangeHash;
            var ecKey = _key;
            var otherPartyKey = ecKey.CreateEcdhKey();
            ECDiffieHellman ephemeralKey = (staticKey is null) ? ECDiffieHellman.Create(ecKey.Crv.CurveParameters) : ((ECJwk)staticKey).CreateEcdhKey();
            try
            {
                exchangeHash = new ReadOnlySpan<byte>(ephemeralKey.DeriveKeyFromHash(otherPartyKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend), 0, _keySizeInBytes);
                var epk = ECJwk.FromParameters(ephemeralKey.ExportParameters(false));
                header.Add(JwtHeaderParameterNames.Epk, epk);
            }
            finally
            {
                if (staticKey is null)
                {
                    ephemeralKey.Dispose();
                }
            }

            SymmetricJwk contentEncryptionKey;
            if (Algorithm.ProduceEncryptionKey)
            {
                using var keyWrapper = new AesKeyWrapper(exchangeHash, EncryptionAlgorithm, _keyManagementAlgorithm!);
                contentEncryptionKey = keyWrapper.WrapKey(null, header, destination);
            }
            else
            {
                exchangeHash.CopyTo(destination);
                contentEncryptionKey = SymmetricJwk.FromSpan(exchangeHash, false);
            }

            return contentEncryptionKey;
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

        private static JsonEncodedText GetPartyInfo(JwtHeader header, JsonEncodedText name)
        {
            if (header.TryGetValue(name, out var token))
            {
                if (token.Type == JwtValueKind.String)
                {
                    return JsonEncodedText.Encode((string)token.Value);
                }
                else
                {
                    return (JsonEncodedText)token.Value!;
                }
            }

            return default;
        }

        private static void WritePartyInfo(ReadOnlySpan<byte> partyInfo, int partyInfoLength, Span<byte> destination)
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
            _algorithm.EncodedUtf8Bytes.CopyTo(destination.Slice(sizeof(int)));
        }

        private byte[] BuildSecretAppend(JsonEncodedText apu, JsonEncodedText apv)
        {
            return BuildSecretAppend(apu.EncodedUtf8Bytes, apv.EncodedUtf8Bytes);
        }

        private byte[] BuildSecretAppend(ReadOnlySpan<byte> apu, ReadOnlySpan<byte> apv)
        {
            int apuLength = apu.IsEmpty ? 0 : Base64Url.GetArraySizeRequiredToDecode(apu.Length);
            int apvLength = apv.IsEmpty ? 0 : Base64Url.GetArraySizeRequiredToDecode(apv.Length);

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
