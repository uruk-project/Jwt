// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

#if SUPPORT_ELLIPTIC_CURVE_KEYWRAPPING
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace JsonWebToken.Internal
{
    internal sealed class EcdhKeyUnwrapper : KeyUnwrapper
    {
        private static readonly byte[] _secretPreprend = { 0x0, 0x0, 0x0, 0x1 };

        private readonly IAlgorithm _algorithm;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly HashAlgorithmName _hashAlgorithm;

        private bool _disposed;

        public EcdhKeyUnwrapper(ECJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
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
        public override int GetKeyUnwrapSize(int inputSize)
        {
            return EncryptionAlgorithm.RequiredKeySizeInBytes;
        }

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, IJwtHeader header, out int bytesWritten)
        {
            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            var epk = header.Epk;
            if (epk is null)
            {
                ThrowHelper.ThrowJwtDescriptorException_HeaderIsRequired(HeaderParameters.EpkUtf8);
            }

            byte[] secretAppend = BuildSecretAppend(header.Apu, header.Apv);
            byte[] exchangeHash;
            using (var ephemeralKey = ECDiffieHellman.Create(epk.ExportParameters()))
            using (var privateKey = ECDiffieHellman.Create(((ECJwk)Key).ExportParameters(true)))
            {
                if (ephemeralKey.KeySize != privateKey.KeySize)
                {
                    return ThrowHelper.TryWriteError(out bytesWritten);
                }

                exchangeHash = privateKey.DeriveKeyFromHash(ephemeralKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);
            }

            if (Algorithm.ProduceEncryptionKey)
            {
                using var key = SymmetricJwk.FromSpan(new ReadOnlySpan<byte>(exchangeHash, 0, _keySizeInBytes), false);
                if (key.TryGetKeyUnwrapper(EncryptionAlgorithm, Algorithm.WrappedAlgorithm, out var keyUnwrapper))
                {
                    return keyUnwrapper.TryUnwrapKey(keyBytes, destination, header, out bytesWritten);
                }
                else
                {
                    return ThrowHelper.TryWriteError(out bytesWritten);
                }
            }
            else
            {
                new ReadOnlySpan<byte>(exchangeHash, 0, _keySizeInBytes).CopyTo(destination);
                bytesWritten = destination.Length;
                return true;
            }
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
            _algorithm.Utf8Name.CopyTo(destination.Slice(sizeof(int)));
        }

        private byte[] BuildSecretAppend(string? apuS, string? apvS)
        {
            byte[]? apuToReturn = null;
            byte[]? apvToReturn = null;
            byte[] secretAppend;
            try
            {
                int apuLength = apuS == null ? 0 : Utf8.GetMaxByteCount(apuS.Length);
                Span<byte> apu = apuLength <= Constants.MaxStackallocBytes
                                        ? stackalloc byte[apuLength]
                                        : (apuToReturn = ArrayPool<byte>.Shared.Rent(apuLength));
                if (apuS != null)
                {
                    apuLength = Utf8.GetBytes(apuS, apu);
                    apu = apu.Slice(0, apuLength);
                }

                int apvLength = apvS == null ? 0 : Utf8.GetMaxByteCount(apvS.Length);
                Span<byte> apv = apvLength <= Constants.MaxStackallocBytes
                                        ? stackalloc byte[apvLength]
                                        : (apvToReturn = ArrayPool<byte>.Shared.Rent(apvLength));
                if (apvS != null)
                {
                    apvLength = Utf8.GetBytes(apvS, apv);
                    apv = apv.Slice(0, apvLength);
                }

                apuLength = Base64Url.GetArraySizeRequiredToDecode(apuLength);
                apvLength = Base64Url.GetArraySizeRequiredToDecode(apvLength);

                int algorithmLength = sizeof(int) + _algorithmNameLength;
                int partyUInfoLength = sizeof(int) + apuLength;
                int partyVInfoLength = sizeof(int) + apvLength;
                const int suppPubInfoLength = sizeof(int);

                int secretAppendLength = algorithmLength + partyUInfoLength + partyVInfoLength + suppPubInfoLength;
                secretAppend = new byte[secretAppendLength];
                var secretAppendSpan = secretAppend.AsSpan();
                WriteAlgorithmId(secretAppendSpan);
                secretAppendSpan = secretAppendSpan.Slice(algorithmLength);
                WritePartyInfo(apu, apuLength, secretAppendSpan);
                secretAppendSpan = secretAppendSpan.Slice(partyUInfoLength);
                WritePartyInfo(apv, apvLength, secretAppendSpan);
                secretAppendSpan = secretAppendSpan.Slice(partyVInfoLength);
                BinaryPrimitives.WriteInt32BigEndian(secretAppendSpan, _keySizeInBytes << 3);
            }
            finally
            {
                if (apuToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(apuToReturn);
                }

                if (apvToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(apvToReturn);
                }
            }

            return secretAppend;
        }
    }
}
#endif
