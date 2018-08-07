#if NETCOREAPP2_1
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken
{

    public class ECKeyWrapProvider : KeyWrapProvider
    {
        private readonly string _finalAlgorithm;
        private readonly int _keyLength;

        public ECKeyWrapProvider(ECJwk key, string encryptionAlgorithm, string contentEncryptionAlgorithm)
        {
            if (contentEncryptionAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(contentEncryptionAlgorithm));
            }

            if (!IsSupportedAlgorithm(contentEncryptionAlgorithm))
            {
                throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, contentEncryptionAlgorithm));
            }

            Algorithm = contentEncryptionAlgorithm;
            Key = key ?? throw new ArgumentNullException(nameof(key));
            EncryptionAlgorithm = encryptionAlgorithm;
            _finalAlgorithm = GetFinalAlgorithm();
            _keyLength = GetKeyLength(_finalAlgorithm);
        }

        private bool IsSupportedAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case KeyManagementAlgorithms.EcdhEs:
                case KeyManagementAlgorithms.EcdhEsAes128KW:
                case KeyManagementAlgorithms.EcdhEsAes192KW:
                case KeyManagementAlgorithms.EcdhEsAes256KW:
                    return true;
                default:
                    return false;
            }
        }

        public override int GetKeyUnwrapSize(int inputSize, string algorithm)
        {
            //return AesKeyWrapProvider.GetKeyUnwrappedSize(inputSize, algorithm);
            switch (algorithm)
            {
                case KeyManagementAlgorithms.EcdhEs:
                    return inputSize;
                case KeyManagementAlgorithms.EcdhEsAes128KW:
                case KeyManagementAlgorithms.EcdhEsAes192KW:
                case KeyManagementAlgorithms.EcdhEsAes256KW:
                    return 32;
                default:
                    throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
            }
        }

        public override int GetKeyWrapSize()
        {
            if (Algorithm == KeyManagementAlgorithms.EcdhEs)
            {
                return _keyLength >> 3;
            }
            else
            {
                return AesKeyWrapProvider.GetKeyWrappedSize(EncryptionAlgorithm);
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

                string algorithm = GetFinalAlgorithm();
                byte[] partyUInfo = GetPartyInfo(header.Apu);
                byte[] partyVInfo = GetPartyInfo(header.Apv);

                var ephemeralJwk = header.Epk;
                var otherPartyPublicKey = CreateECDiffieHellman(ephemeralJwk).PublicKey;
                var privateKey = CreateECDiffieHellman();

                int secretPrependLength = sizeof(int);
                int algorithmLength = sizeof(int) + Encoding.ASCII.GetByteCount(algorithm);
                int partyUInfoLength = sizeof(int) + partyUInfo.Length;
                int partyVInfoLength = sizeof(int) + partyVInfo.Length;
                int suppPubInfoLength = sizeof(int);

                int secretAppendLength = algorithmLength + partyUInfoLength + partyVInfoLength + suppPubInfoLength;
                Span<byte> secretPrepend = stackalloc byte[secretPrependLength];
                Span<byte> secretAppend = stackalloc byte[secretAppendLength];

                WriteRoundNumber(secretPrepend);
                WriteAlgorithmId(algorithm, secretAppend);
                WritePartyInfo(partyUInfo, secretAppend.Slice(algorithmLength));
                WritePartyInfo(partyVInfo, secretAppend.Slice(algorithmLength + partyUInfoLength));
                WriteSuppInfo(algorithm, secretAppend.Slice(algorithmLength + partyUInfoLength + partyVInfoLength));

                var hashAlgorithm = GetHashAlgorithm(algorithm);
                var exchangeHash = privateKey.DeriveKeyFromHash(otherPartyPublicKey, hashAlgorithm, secretPrepend.ToArray(), secretAppend.ToArray());

                var isDirectEncryption = Algorithm == KeyManagementAlgorithms.EcdhEs;
                if (!isDirectEncryption)
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

        private (int, string) GetAesAlgorithm()
        {
            switch (Algorithm)
            {
                case KeyManagementAlgorithms.EcdhEsAes128KW:
                    return (16,  KeyManagementAlgorithms.Aes128KW);
                case KeyManagementAlgorithms.EcdhEsAes192KW:
                    return (24, KeyManagementAlgorithms.Aes192KW);
                case KeyManagementAlgorithms.EcdhEsAes256KW:
                    return (32, KeyManagementAlgorithms.Aes256KW);
                default:
                    throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, EncryptionAlgorithm));
            }
        }

        private static HashAlgorithmName GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return HashAlgorithmName.SHA384;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return HashAlgorithmName.SHA512;
                default:
                    return HashAlgorithmName.SHA256;
            }
        }

        private ECDiffieHellman CreateECDiffieHellman()
        {
            return CreateECDiffieHellman((ECJwk)Key);
        }

        private static ECDiffieHellman CreateECDiffieHellman(ECJwk key)
        {
            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportParameters(key.ToParameters());
            return ecdh;
        }

        private static ECDiffieHellmanPublicKey CreateEcdhPublicKey(ECJwk key)
        {
            return CreateECDiffieHellman(key).PublicKey;
        }

        public override bool TryWrapKey(JsonWebKey staticKey, JObject header, Span<byte> destination, out JsonWebKey contentEncryptionKey, out int bytesWritten)
        {
            try
            {
                using (var ephemeralKey = (staticKey == null) ? ECDiffieHellman.Create() : ECDiffieHellman.Create(((ECJwk)staticKey).ToParameters()))
                {
                    if (staticKey == null)
                    {
                        ephemeralKey.GenerateKey(ECCurve.NamedCurves.nistP256);
                    }

                    var otherPartyPublicKey = CreateEcdhPublicKey((ECJwk)Key);

                    byte[] partyUInfo = GetPartyInfo(header, HeaderParameters.Apu);
                    byte[] partyVInfo = GetPartyInfo(header, HeaderParameters.Apv);
                    
                    int secretPrependLength = sizeof(int);
                    int algorithmLength = sizeof(int) + Encoding.ASCII.GetByteCount(_finalAlgorithm);
                    int partyUInfoLength = sizeof(int) + partyUInfo.Length;
                    int partyVInfoLength = sizeof(int) + partyVInfo.Length;
                    int suppPubInfoLength = sizeof(int);

                    int secretAppendLength = algorithmLength + partyUInfoLength + partyVInfoLength + suppPubInfoLength;
                    Span<byte> secretPrepend = stackalloc byte[secretPrependLength];
                    Span<byte> secretAppend = stackalloc byte[secretAppendLength];

                    WriteRoundNumber(secretPrepend);
                    WriteAlgorithmId(_finalAlgorithm, secretAppend);
                    WritePartyInfo(partyUInfo, secretAppend.Slice(algorithmLength));
                    WritePartyInfo(partyVInfo, secretAppend.Slice(algorithmLength + partyUInfoLength));
                    WriteSuppInfo(_finalAlgorithm, secretAppend.Slice(algorithmLength + partyUInfoLength + partyVInfoLength));

                    var hashAlgorithm = GetHashAlgorithm(_finalAlgorithm);
                    var exchangeHash = ephemeralKey.DeriveKeyFromHash(otherPartyPublicKey, hashAlgorithm, secretPrepend.ToArray(), secretAppend.ToArray());

                    var epk = ECJwk.FromParameters(ephemeralKey.ExportParameters(false));
                    header.Add(HeaderParameters.Epk, JToken.FromObject(epk));

                    bool isDirectEncryption = Algorithm == KeyManagementAlgorithms.EcdhEs;

                    if (!isDirectEncryption)
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
                        exchangeHash.AsSpan(0, _keyLength >> 3).CopyTo(destination);
                        bytesWritten = destination.Length;
                        contentEncryptionKey = SymmetricJwk.FromSpan(destination, false);
                        return true;
                    }
                }
            }
            catch
            {
                contentEncryptionKey = null;
                bytesWritten = 0;
                return false;
            }
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

        private void WriteRoundNumber(Span<byte> destination)
        {
            BitConverter.TryWriteBytes(destination, 1);
            if (BitConverter.IsLittleEndian)
            {
                destination.Slice(0, 4).Reverse();
            }
        }

        private void WriteSuppInfo(string algorithm, Span<byte> destination)
        {
            BitConverter.TryWriteBytes(destination, GetKeyLength(algorithm));
            if (BitConverter.IsLittleEndian)
            {
                destination.Slice(0, 4).Reverse();
            }
        }

        private void WritePartyInfo(byte[] partyInfo, Span<byte> destination)
        {
            if (partyInfo.Length == 0)
            {
                BitConverter.TryWriteBytes(destination, 0);
            }
            else
            {
                BitConverter.TryWriteBytes(destination, partyInfo.Length);
                if (BitConverter.IsLittleEndian)
                {
                    destination.Slice(0, 4).Reverse();
                }

                partyInfo.CopyTo(destination.Slice(4));
            }
        }

        private string GetFinalAlgorithm()
        {
            switch (Algorithm)
            {
                case KeyManagementAlgorithms.EcdhEs:
                    return EncryptionAlgorithm;
                case KeyManagementAlgorithms.EcdhEsAes128KW:
                case KeyManagementAlgorithms.EcdhEsAes192KW:
                case KeyManagementAlgorithms.EcdhEsAes256KW:
                    return Algorithm;
                default:
                    throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, Algorithm));
            }
        }

        private void WriteAlgorithmId(string algorithm, Span<byte> destination)
        {
            BitConverter.TryWriteBytes(destination, Encoding.ASCII.GetByteCount(algorithm));
            if (BitConverter.IsLittleEndian)
            {
                destination.Slice(0, 4).Reverse();
            }

            Encoding.ASCII.GetBytes(algorithm, destination.Slice(4));
        }

        private int GetKeyLength(string algorithm)
        {
            switch (algorithm)
            {
                case KeyManagementAlgorithms.EcdhEsAes128KW:
                case ContentEncryptionAlgorithms.Aes128Gcm:
                    return 128;
                case KeyManagementAlgorithms.EcdhEsAes192KW:
                case ContentEncryptionAlgorithms.Aes192Gcm:
                    return 192;
                case KeyManagementAlgorithms.EcdhEsAes256KW:
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                case ContentEncryptionAlgorithms.Aes256Gcm:
                    return 256;
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return 384;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return 512;
             }

            throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, Algorithm));
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
#endif