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
    internal sealed class EcdhKeyUnwrapper : KeyUnwrapper
    {
        private const int Sha256Length = 32;
        private static readonly byte[] _secretPreprend = { 0x0, 0x0, 0x0, 0x1 };

        private readonly JsonEncodedText _algorithm;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly KeyManagementAlgorithm? _keyManagementAlgorithm;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly ECJwk _key;

        public EcdhKeyUnwrapper(ECJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
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
            _hashAlgorithm = GetHashAlgorithm();
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int inputSize)
            => EncryptionAlgorithm.RequiredKeySizeInBytes;

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeaderDocument header, out int bytesWritten)
        {
            if (!header.TryGetHeaderParameter(JwtHeaderParameterNames.Epk.EncodedUtf8Bytes, out var epk))
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(JwtHeaderParameterNames.Epk);
            }

            header.TryGetHeaderParameter(JwtHeaderParameterNames.Apu.EncodedUtf8Bytes, out JwtElement apu);
            header.TryGetHeaderParameter(JwtHeaderParameterNames.Apv.EncodedUtf8Bytes, out JwtElement apv);
            byte[] secretAppend = BuildSecretAppend(apu, apv);

            Span<byte> exchangeHash = stackalloc byte[_keySizeInBytes];
            if (_keySizeInBytes > Sha256Length)
            {
                exchangeHash.Slice(Sha256Length).Clear();
            }

            using (var ephemeralKey = ECDiffieHellman.Create(ECJwk.FromJwtElement(epk).ExportParameters()))
            {
                var privateKey = _key.CreateEcdhKey();
                if (ephemeralKey.KeySize != privateKey.KeySize)
                {
                    return ThrowHelper.TryWriteError(out bytesWritten);
                }

                var kdf = privateKey.DeriveKeyFromHash(ephemeralKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);
                kdf.AsSpan(0, _keySizeInBytes < kdf.Length ? _keySizeInBytes : kdf.Length).CopyTo(exchangeHash);
            }

            if (Algorithm.ProduceEncryptionKey)
            {
                using var keyUnwrapper = new AesKeyUnwrapper(exchangeHash, EncryptionAlgorithm, _keyManagementAlgorithm!);
                return keyUnwrapper.TryUnwrapKey(keyBytes, destination, header, out bytesWritten);
            }
            else
            {
                exchangeHash.CopyTo(destination);
                bytesWritten = destination.Length;
                return true;
            }
        }

        protected override void Dispose(bool disposing)
        {
        }

        private static HashAlgorithmName GetHashAlgorithm()
        {
            return HashAlgorithmName.SHA256;
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

        private byte[] BuildSecretAppend(JwtElement apuS, JwtElement apvS)
        {
            var apu = apuS.IsEmpty ? default : apuS.GetRawValue();
            var apv = apvS.IsEmpty ? default : apvS.GetRawValue();
            int apuLength = Base64Url.GetArraySizeRequiredToDecode(apu.Length);
            int apvLength = Base64Url.GetArraySizeRequiredToDecode(apv.Length);

            int algorithmLength = sizeof(int) + _algorithmNameLength;
            int partyUInfoLength = sizeof(int) + apuLength;
            int partyVInfoLength = sizeof(int) + apvLength;
            const int suppPubInfoLength = sizeof(int);

            int secretAppendLength = algorithmLength + partyUInfoLength + partyVInfoLength + suppPubInfoLength;
            var secretAppend = new byte[secretAppendLength];
            var secretAppendSpan = secretAppend.AsSpan(0, secretAppendLength);
            WriteAlgorithmId(secretAppendSpan);
            secretAppendSpan = secretAppendSpan.Slice(algorithmLength);
            WritePartyInfo(apu.Span, apuLength, secretAppendSpan);
            secretAppendSpan = secretAppendSpan.Slice(partyUInfoLength);
            WritePartyInfo(apv.Span, apvLength, secretAppendSpan);
            secretAppendSpan = secretAppendSpan.Slice(partyVInfoLength);
            BinaryPrimitives.WriteInt32BigEndian(secretAppendSpan, _keySizeInBytes << 3);

            return secretAppend;
        }
    }
}
#endif
