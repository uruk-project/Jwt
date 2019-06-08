// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken.Internal
{
#if !NETSTANDARD2_0
    internal sealed class EcdhKeyWrapper : KeyWrapper
    {
        private static readonly byte[] _secretPreprend = { 0x0, 0x0, 0x0, 0x1 };

        private readonly byte[] _algorithmName;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly HashAlgorithmName _hashAlgorithm;

        private bool _disposed;

        public EcdhKeyWrapper(ECJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
            : base(key, encryptionAlgorithm, contentEncryptionAlgorithm)
        {
            if (contentEncryptionAlgorithm == KeyManagementAlgorithm.EcdhEs)
            {
                _algorithmName = encryptionAlgorithm.Utf8Name;
                _keySizeInBytes = encryptionAlgorithm.RequiredKeySizeInBytes;
            }
            else
            {
                _algorithmName = contentEncryptionAlgorithm.Utf8Name;
                _keySizeInBytes = contentEncryptionAlgorithm.WrappedAlgorithm.RequiredKeySizeInBits >> 3;
            }

            _algorithmNameLength = _algorithmName.Length;
            _hashAlgorithm = GetHashAlgorithm(encryptionAlgorithm);
        }

        /// <inheritsdoc />
        public override int GetKeyUnwrapSize(int inputSize)
        {
            return EncryptionAlgorithm.RequiredKeySizeInBytes;
        }

        /// <inheritsdoc />
        public override int GetKeyWrapSize()
        {
            if (Algorithm == KeyManagementAlgorithm.EcdhEs)
            {
                return _keySizeInBytes;
            }
            else
            {
#if NETCOREAPP3_0
                if (EncryptionAlgorithm.Category == EncryptionType.AesGcm)
                {
                    return _keySizeInBytes + 8;
                }
#endif
                return EncryptionAlgorithm.KeyWrappedSizeInBytes;
            }
        }

        /// <inheritsdoc />
        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var epk = header.Epk;
            if (header.Epk is null)
            {
                return Errors.TryWriteError(out bytesWritten);
            }

            var apu = header.Apu == null ? null : Encoding.UTF8.GetBytes(header.Apu);
            var apv = header.Apv == null ? null : Encoding.UTF8.GetBytes(header.Apv);
            byte[] secretAppend = BuildSecretAppend(apu, apv);
            var ephemeralJwk = epk;
            byte[] exchangeHash;
            using (var ephemeralKey = ECDiffieHellman.Create(ephemeralJwk.ExportParameters()))
            using (var privateKey = ECDiffieHellman.Create(((ECJwk)Key).ExportParameters(true)))
            {
                exchangeHash = privateKey.DeriveKeyFromHash(ephemeralKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);
            }

            if (Algorithm.ProduceEncryptionKey)
            {
                var key = SymmetricJwk.FromSpan(new ReadOnlySpan<byte>(exchangeHash, 0, _keySizeInBytes), false);
                using (KeyWrapper keyWrapper = key.CreateKeyWrapper(EncryptionAlgorithm, Algorithm.WrappedAlgorithm))
                {
                    return keyWrapper.TryUnwrapKey(keyBytes, destination, header, out bytesWritten);
                }
            }
            else
            {
                new ReadOnlySpan<byte>(exchangeHash, 0, _keySizeInBytes).CopyTo(destination);
                bytesWritten = destination.Length;
                return true;
            }
        }

        /// <inheritsdoc />
        public override bool TryWrapKey(Jwk staticKey, JwtObject header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            var partyUInfo = GetPartyInfo(header, HeaderParameters.ApuUtf8);
            var partyVInfo = GetPartyInfo(header, HeaderParameters.ApvUtf8);
            var secretAppend = BuildSecretAppend(partyUInfo, partyVInfo);
            byte[] exchangeHash;
            using (var ephemeralKey = (staticKey is null) ? ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256) : ECDiffieHellman.Create(((ECJwk)staticKey).ExportParameters(true)))
            using (var otherPartyKey = ECDiffieHellman.Create(((ECJwk)Key).ExportParameters()))
            {
                exchangeHash = ephemeralKey.DeriveKeyFromHash(otherPartyKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);
                var epk = ECJwk.FromParameters(ephemeralKey.ExportParameters(false));
                header.Add(new JwtProperty(HeaderParameters.EpkUtf8, epk.AsJwtObject()));
            }

            var kek = SymmetricJwk.FromSpan(new ReadOnlySpan<byte>(exchangeHash, 0, _keySizeInBytes), false);
            if (Algorithm.ProduceEncryptionKey)
            {
                using (KeyWrapper keyWrapper = kek.CreateKeyWrapper(EncryptionAlgorithm, Algorithm.WrappedAlgorithm))
                {
                    return keyWrapper.TryWrapKey(null, header, destination, out contentEncryptionKey, out bytesWritten);
                }
            }
            else
            {
                contentEncryptionKey = kek;
                bytesWritten = _keySizeInBytes;
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

        private static byte[] GetPartyInfo(JwtObject header, ReadOnlySpan<byte> utf8Name)
        {
            if (header.TryGetValue(utf8Name, out var token))
            {
                return (byte[])token.Value;
            }

            return null;
        }

        private static void WritePartyInfo(byte[] partyInfo, int partyInfoLength, Span<byte> destination)
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
            _algorithmName.CopyTo( destination.Slice(sizeof(int)));
        }

        private byte[] BuildSecretAppend(byte[] apu, byte[] apv)
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
            WritePartyInfo(apu, apuLength, secretAppendSpan.Slice(algorithmLength));
            WritePartyInfo(apv, apvLength, secretAppendSpan.Slice(algorithmLength + partyUInfoLength));
            BinaryPrimitives.WriteInt32BigEndian(secretAppendSpan.Slice(algorithmLength + partyUInfoLength + partyVInfoLength), _keySizeInBytes << 3);

            return secretAppend;
        }
    }
#else
    internal sealed class EcdhKeyWrapper : KeyWrapper
    {
        public EcdhKeyWrapper(Jwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
            : base(key, encryptionAlgorithm, algorithm)
        {
        }

        public override int GetKeyUnwrapSize(int wrappedKeySize)
        {
            throw new NotImplementedException();
        }

        public override int GetKeyWrapSize()
        {
            throw new NotImplementedException();
        }

        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            throw new NotImplementedException();
        }

        public override bool TryWrapKey(Jwk staticKey, JwtObject header, Span<byte> destination, out Jwk contentEncryptionKey, out int bytesWritten)
        {
            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            throw new NotImplementedException();
        }
    }
#endif
}
