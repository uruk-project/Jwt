#if NETCOREAPP2_1
using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken.Internal
{
    public sealed class EcdhKeyWrapper : KeyWrapper
    {
        private static readonly byte[] _secretPreprend = { 0x0, 0x0, 0x0, 0x1 };
        private static readonly uint OneBigEndian = BitConverter.IsLittleEndian ? 0x1000000u : 1u;

        private readonly string _algorithmName;
        private readonly int _algorithmNameLength;
        private readonly int _keySizeInBytes;
        private readonly HashAlgorithmName _hashAlgorithm;

        private bool _disposed;

        public EcdhKeyWrapper(ECJwk key, EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
            : base(key, encryptionAlgorithm, contentEncryptionAlgorithm)
        {
            if (contentEncryptionAlgorithm == KeyManagementAlgorithm.EcdhEs)
            {
                _algorithmName = encryptionAlgorithm.Name;
                _keySizeInBytes = encryptionAlgorithm.RequiredKeySizeInBytes;
            }
            else
            {
                _algorithmName = contentEncryptionAlgorithm.Name;
                _keySizeInBytes = contentEncryptionAlgorithm.WrappedAlgorithm.RequiredKeySizeInBits >> 3;
            }

            _algorithmNameLength = Encoding.ASCII.GetByteCount(_algorithmName);
            _hashAlgorithm = GetHashAlgorithm(encryptionAlgorithm);
        }

        public override int GetKeyUnwrapSize(int inputSize)
        {
            return EncryptionAlgorithm.RequiredKeySizeInBytes;
        }

        public override int GetKeyWrapSize()
        {
            if (Algorithm == KeyManagementAlgorithm.EcdhEs)
            {
                return _keySizeInBytes;
            }
            else
            {
                return EncryptionAlgorithm.RequiredKeyWrappedSizeInBytes;
            }
        }

        public override bool TryUnwrapKey(ReadOnlySpan<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            try
            {
                if (header.Epk == null)
                {
                    return Errors.TryWriteError(out bytesWritten);
                }

                byte[] secretAppend = BuildSecretAppend(header.Apu, header.Apv);
                var ephemeralJwk = header.Epk;
                byte[] exchangeHash;
                using (var ephemeralKey = ECDiffieHellman.Create(ephemeralJwk.ExportParameters()))
                using (var privateKey = ECDiffieHellman.Create(((ECJwk)Key).ExportParameters(true)))
                {
                    exchangeHash = privateKey.DeriveKeyFromHash(ephemeralKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);
                }

                if (Algorithm.ProduceEncryptedKey)
                {
                    var key = SymmetricJwk.FromSpan(exchangeHash.AsSpan(0, _keySizeInBytes), false);
                    using (KeyWrapper aesKeyWrapProvider = key.CreateKeyWrapper(EncryptionAlgorithm, Algorithm.WrappedAlgorithm))
                    {
                        return aesKeyWrapProvider.TryUnwrapKey(keyBytes, destination, header, out bytesWritten);
                    }
                }
                else
                {
                    exchangeHash.AsSpan(0, _keySizeInBytes).CopyTo(destination);
                    bytesWritten = destination.Length;
                    return true;
                }
            }
            catch
            {
                return Errors.TryWriteError(out bytesWritten);
            }
        }

        private static HashAlgorithmName GetHashAlgorithm(EncryptionAlgorithm encryptionAlgorithm)
        {
            var hashAlgorithm = encryptionAlgorithm.SignatureAlgorithm.HashAlgorithm;
            if (hashAlgorithm == default)
            {
                return HashAlgorithmName.SHA256;
            }

            return hashAlgorithm;
        }

        public override bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            try
            {
                var partyUInfo = GetPartyInfo(header, HeaderParameters.Apu);
                var partyVInfo = GetPartyInfo(header, HeaderParameters.Apv);
                var secretAppend = BuildSecretAppend(partyUInfo, partyVInfo);
                byte[] exchangeHash;
                using (var ephemeralKey = (staticKey == null) ? ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256) : ECDiffieHellman.Create(((ECJwk)staticKey).ExportParameters(true)))
                using (var otherPartyKey = ECDiffieHellman.Create(((ECJwk)Key).ExportParameters()))
                {
                    exchangeHash = ephemeralKey.DeriveKeyFromHash(otherPartyKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);

                    var epk = ECJwk.FromParameters(ephemeralKey.ExportParameters(false));
                    header.Add(HeaderParameters.Epk, JToken.FromObject(epk));
                }

                if (Algorithm.ProduceEncryptedKey)
                {
                    var kek = SymmetricJwk.FromSpan(exchangeHash.AsSpan(0, _keySizeInBytes), false);
                    using (KeyWrapper aesKeyWrapProvider = kek.CreateKeyWrapper(EncryptionAlgorithm, Algorithm.WrappedAlgorithm))
                    {
                        return aesKeyWrapProvider.TryWrapKey(null, header, destination, out contentEncryptionKey, out bytesWritten);
                    }
                }
                else
                {
                    contentEncryptionKey = SymmetricJwk.FromSpan(exchangeHash.AsSpan(0, _keySizeInBytes), false);
                    bytesWritten = 0;
                    return true;
                }
            }
            catch
            {
                contentEncryptionKey = null;
                return Errors.TryWriteError(out bytesWritten);
            }
        }

        private static string GetPartyInfo(JObject header, string headerName)
        {
            if (header.TryGetValue(headerName, out var token))
            {
                return token.Value<string>();
            }

            return null;
        }

        private static byte[] GetPartyInfo(string header)
        {
            byte[] partyInfo = null;
            if (header != null)
            {
                partyInfo = Base64Url.Base64UrlDecode(header);
            }

            return partyInfo ?? Array.Empty<byte>();
        }

        private static void WriteRoundNumber(Span<byte> destination)
        {
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), OneBigEndian);
        }

        private void WriteSuppInfo(Span<byte> destination)
        {
            BinaryPrimitives.WriteInt32BigEndian(destination, _keySizeInBytes << 3);
        }

        private static void WriteZero(Span<byte> destination)
        {
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), 0);
        }

        private static void WritePartyInfo(string partyInfo, int partyInfoLength, Span<byte> destination)
        {
            if (partyInfoLength == 0)
            {
                WriteZero(destination);
            }
            else
            {
                BinaryPrimitives.WriteInt32BigEndian(destination, partyInfoLength);
                Base64Url.Base64UrlDecode(partyInfo, destination.Slice(sizeof(int)));
            }
        }

        private void WriteAlgorithmId(Span<byte> destination)
        {
            BinaryPrimitives.WriteInt32BigEndian(destination, _algorithmNameLength);
            Encoding.ASCII.GetBytes(_algorithmName, destination.Slice(sizeof(int)));
        }

        private byte[] BuildSecretAppend(string apu, string apv)
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
            WriteAlgorithmId(secretAppend);
            WritePartyInfo(apu, apuLength, secretAppendSpan.Slice(algorithmLength));
            WritePartyInfo(apv, apvLength, secretAppendSpan.Slice(algorithmLength + partyUInfoLength));
            WriteSuppInfo(secretAppendSpan.Slice(algorithmLength + partyUInfoLength + partyVInfoLength));

            return secretAppend;
        }

        protected override void Dispose(bool disposing)
        {
            _disposed = true;
        }
    }
}
#endif