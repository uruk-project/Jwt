#if NETCOREAPP2_1
using Newtonsoft.Json.Linq;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken
{
    public class EcdhKeyWrapProvider : KeyWrapProvider
    {
        private readonly string _algorithmName;
        private readonly int _algorithmNameLength;
        private readonly int _keyLength;
        private readonly HashAlgorithmName _hashAlgorithm;

        private static readonly byte[] _secretPreprend = { 0x0, 0x0, 0x0, 0x1 };
        private static readonly uint OneBigEndian = BitConverter.IsLittleEndian ? 0x1000000u : 1u;

        public EcdhKeyWrapProvider(EccJwk key, in EncryptionAlgorithm encryptionAlgorithm, in KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            
            if (!key.IsSupportedAlgorithm(contentEncryptionAlgorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, contentEncryptionAlgorithm));
            }

            Algorithm = contentEncryptionAlgorithm;
            Key = key ?? throw new ArgumentNullException(nameof(key));
            EncryptionAlgorithm = encryptionAlgorithm;
            _algorithmName = GetAlgorithmName();
            _algorithmNameLength = Encoding.ASCII.GetByteCount(_algorithmName);
            _keyLength = GetKeyLength(contentEncryptionAlgorithm, encryptionAlgorithm);
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
                return _keyLength >> 3;
            }
            else
            {
                return EncryptionAlgorithm.RequiredKeyWrappedSizeInBytes;
            }
        }

        public override bool TryUnwrapKey(Span<byte> keyBytes, Span<byte> destination, JwtHeader header, out int bytesWritten)
        {
            try
            {
                if (header.Epk == null)
                {
                    bytesWritten = 0;
                    return false;
                }

                byte[] partyUInfo = GetPartyInfo(header.Apu);
                byte[] partyVInfo = GetPartyInfo(header.Apv);

                byte[] secretAppend = BuildSecretAppend(partyUInfo, partyVInfo);
                var ephemeralJwk = header.Epk;
                byte[] exchangeHash;
                using (var ephemeralKey = ECDiffieHellman.Create(ephemeralJwk.ExportParameters()))
                using (var privateKey = ECDiffieHellman.Create(((EccJwk)Key).ExportParameters(true)))
                {
                    exchangeHash = privateKey.DeriveKeyFromHash(ephemeralKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);
                }

                if (Algorithm.ProduceEncryptedKey)
                {
                    var (keyLength, aesAlgorithm) = GetAesAlgorithm();

                    var key = SymmetricJwk.FromSpan(exchangeHash.AsSpan(0, keyLength), false);
                    KeyWrapProvider aesKeyWrapProvider = key.CreateKeyWrapProvider(EncryptionAlgorithm, aesAlgorithm);
                    try
                    {
                        return aesKeyWrapProvider.TryUnwrapKey(keyBytes, destination, header, out bytesWritten);
                    }
                    finally
                    {
                        key.ReleaseKeyWrapProvider(aesKeyWrapProvider);
                    }
                }
                else
                {
                    exchangeHash.AsSpan(0, _keyLength >> 3).CopyTo(destination);
                    bytesWritten = destination.Length;
                    return true;
                }
            }
            catch
            {
                bytesWritten = 0;
                return false;
            }
        }

        private (int, KeyManagementAlgorithm) GetAesAlgorithm()
        {
            KeyManagementAlgorithm aesAlgorithm = (KeyManagementAlgorithm)Algorithm.WrappedAlgorithm;
            return (aesAlgorithm.RequiredKeySizeInBits >> 3, aesAlgorithm);
        }

        private static HashAlgorithmName GetHashAlgorithm(in EncryptionAlgorithm encryptionAlgorithm)
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
            try
            {
                var partyUInfo = GetPartyInfo(header, HeaderParameters.Apu);
                var partyVInfo = GetPartyInfo(header, HeaderParameters.Apv);
                var secretAppend = BuildSecretAppend(partyUInfo, partyVInfo);
                byte[] exchangeHash;
                using (var ephemeralKey = (staticKey == null) ? ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256) : ECDiffieHellman.Create(((EccJwk)staticKey).ExportParameters(true)))
                using (var otherPartyKey = ECDiffieHellman.Create(((EccJwk)Key).ExportParameters()))
                {
                    exchangeHash = ephemeralKey.DeriveKeyFromHash(otherPartyKey.PublicKey, _hashAlgorithm, _secretPreprend, secretAppend);

                    var epk = EccJwk.FromParameters(ephemeralKey.ExportParameters(false));
                    header.Add(HeaderParameters.Epk, JToken.FromObject(epk));
                }

                if (Algorithm.ProduceEncryptedKey)
                {
                    var (keyLength, aesAlgorithm) = GetAesAlgorithm();
                    var kek = SymmetricJwk.FromSpan(exchangeHash.AsSpan(0, keyLength), false);
                    KeyWrapProvider aesKeyWrapProvider = kek.CreateKeyWrapProvider(EncryptionAlgorithm, aesAlgorithm);
                    try
                    {
                        return aesKeyWrapProvider.TryWrapKey(null, header, destination, out contentEncryptionKey, out bytesWritten);
                    }
                    finally
                    {
                        kek.ReleaseKeyWrapProvider(aesKeyWrapProvider);
                    }
                }
                else
                {
                    bytesWritten = 0;
                    contentEncryptionKey = SymmetricJwk.FromSpan(exchangeHash.AsSpan(0, _keyLength >> 3), false);
                    return true;
                }
            }
            catch
            {
                contentEncryptionKey = null;
                bytesWritten = 0;
                return false;
            }
        }

        private string GetAlgorithmName()
        {
            if (Algorithm == KeyManagementAlgorithm.EcdhEs)
            {
                return EncryptionAlgorithm.Name;
            }

            return Algorithm.Name;
        }

        private static byte[] GetPartyInfo(JObject header, string headerName)
        {
            byte[] partyInfo = null;
            if (header.TryGetValue(headerName, out var token))
            {
                partyInfo = token.Annotation<byte[]>();
                if (partyInfo == null)
                {
                    partyInfo = Base64Url.Base64UrlDecode(token.Value<string>());
                }
            }

            return partyInfo ?? Array.Empty<byte>();
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

        private static unsafe void WriteRoundNumber(Span<byte> destination)
        {
            fixed (byte* ptr = &MemoryMarshal.GetReference(destination))
            {
                Unsafe.WriteUnaligned(ptr, OneBigEndian);
            }
        }

        private void WriteSuppInfo(Span<byte> destination)
        {
            BinaryPrimitives.WriteInt32BigEndian(destination, _keyLength);
        }

        private static unsafe void WriteZero(Span<byte> destination)
        {
            fixed (byte* ptr = &MemoryMarshal.GetReference(destination))
            {
                Unsafe.WriteUnaligned(ptr, 0);
            }
        }
        
        private static void WritePartyInfo(Span<byte> partyInfo, Span<byte> destination)
        {
            if (partyInfo.IsEmpty)
            {
                WriteZero(destination);
            }
            else
            {
                BinaryPrimitives.WriteInt32BigEndian(destination, partyInfo.Length);
                partyInfo.CopyTo(destination.Slice(sizeof(int)));
            }
        }

        private void WriteAlgorithmId(Span<byte> destination)
        {
            BinaryPrimitives.WriteInt32BigEndian(destination, _algorithmNameLength);
            Encoding.ASCII.GetBytes(_algorithmName, destination.Slice(sizeof(int)));
        }

        private byte[] BuildSecretAppend(byte[] partyUInfo, byte[] partyVInfo)
        {
            int algorithmLength = sizeof(int) + _algorithmNameLength;
            int partyUInfoLength = sizeof(int) + partyUInfo.Length;
            int partyVInfoLength = sizeof(int) + partyVInfo.Length;
            const int suppPubInfoLength = sizeof(int);

            int secretAppendLength = algorithmLength + partyUInfoLength + partyVInfoLength + suppPubInfoLength;
            var secretAppend = new byte[secretAppendLength];
            var secretAppendSpan = secretAppend.AsSpan();
            WriteAlgorithmId(secretAppend);
            WritePartyInfo(partyUInfo, secretAppendSpan.Slice(algorithmLength));
            WritePartyInfo(partyVInfo, secretAppendSpan.Slice(algorithmLength + partyUInfoLength));
            WriteSuppInfo(secretAppendSpan.Slice(algorithmLength + partyUInfoLength + partyVInfoLength));

            return secretAppend;
        }

        private static int GetKeyLength(in KeyManagementAlgorithm algorithm, in EncryptionAlgorithm encryptionAlgorithm)
        {
            if (algorithm == KeyManagementAlgorithm.EcdhEs)
            {
                return encryptionAlgorithm.RequiredKeySizeInBytes << 3;
            }
            else
            {
                return ((KeyManagementAlgorithm)algorithm.WrappedAlgorithm).RequiredKeySizeInBits;
            }
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
#endif