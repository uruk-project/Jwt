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
            _keyLength = GetKeyLength(GetAlgorithm());
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
            //switch (algorithm)
            //{
            //    case KeyManagementAlgorithms.EcdhEs:
            //        return inputSize;
            //    case KeyManagementAlgorithms.EcdhEsAes128KW:
            //        return 32;
            //    case KeyManagementAlgorithms.EcdhEsAes192KW:
            //        return 48;
            //    case KeyManagementAlgorithms.EcdhEsAes256KW:
            //        return 64;
                return AesKeyWrapProvider.GetKeyUnwrappedSize(inputSize, algorithm);
            //    default:
            //        throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, algorithm));
            //}
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

                string algorithm = GetAlgorithm();
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

                var exchangeHash = privateKey.DeriveKeyFromHash(otherPartyPublicKey, HashAlgorithmName.SHA256, secretPrepend.ToArray(), secretAppend.ToArray());

                var isDirectEncryption = Algorithm == KeyManagementAlgorithms.EcdhEs;
                if (!isDirectEncryption)
                {
                    int keyLength;
                    string aesAlgorithm;
                    switch (Algorithm)
                    {
                        case KeyManagementAlgorithms.EcdhEsAes128KW:
                            aesAlgorithm = KeyManagementAlgorithms.Aes128KW;
                            keyLength = 16;
                            break;
                        case KeyManagementAlgorithms.EcdhEsAes192KW:
                            aesAlgorithm = KeyManagementAlgorithms.Aes192KW;
                            keyLength = 24;
                            break;
                        case KeyManagementAlgorithms.EcdhEsAes256KW:
                            aesAlgorithm = KeyManagementAlgorithms.Aes256KW;
                            keyLength = 32;
                            break;
                        default:
                            throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, EncryptionAlgorithm));
                    }

                    var key = SymmetricJwk.FromSpan(exchangeHash.AsSpan(0, keyLength), false);
                    KeyWrapProvider kwp = key.CreateKeyWrapProvider(EncryptionAlgorithm, aesAlgorithm);
                    try
                    {
                        return kwp.TryUnwrapKey(keyBytes, destination, header, out bytesWritten);
                    }
                    finally
                    {
                        key.ReleaseKeyWrapProvider(kwp);
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

                    string algorithm = GetAlgorithm();

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

                    var exchangeHash = ephemeralKey.DeriveKeyFromHash(otherPartyPublicKey, HashAlgorithmName.SHA256, secretPrepend.ToArray(), secretAppend.ToArray());

                    var epk = ECJwk.FromParameters(ephemeralKey.ExportParameters(false));
                    header.Add(HeaderParameters.Epk, JToken.FromObject(epk));

                    bool isDirectEncryption = Algorithm == KeyManagementAlgorithms.EcdhEs;

                    if (!isDirectEncryption)
                    {
                        int keyLength;
                        string aesAlgorithm;
                        switch (Algorithm)
                        {
                            case KeyManagementAlgorithms.EcdhEsAes128KW:
                                aesAlgorithm = KeyManagementAlgorithms.Aes128KW;
                                keyLength = 16;
                                break;
                            case KeyManagementAlgorithms.EcdhEsAes192KW:
                                aesAlgorithm = KeyManagementAlgorithms.Aes192KW;
                                keyLength = 24;
                                break;
                            case KeyManagementAlgorithms.EcdhEsAes256KW:
                                aesAlgorithm = KeyManagementAlgorithms.Aes256KW;
                                keyLength = 32;
                                break;
                            default:
                                throw new JsonWebTokenEncryptionFailedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, EncryptionAlgorithm));
                        }

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

        private string GetAlgorithm()
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
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    return 256;
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return 384;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return 512;
                case ContentEncryptionAlgorithms.Aes128Gcm:
                    return 128;
                case ContentEncryptionAlgorithms.Aes192Gcm:
                    return 192;
                case ContentEncryptionAlgorithms.Aes256Gcm:
                    return 256;
                case KeyManagementAlgorithms.EcdhEsAes128KW:
                    return 128;
                case KeyManagementAlgorithms.EcdhEsAes192KW:
                    return 192;
                case KeyManagementAlgorithms.EcdhEsAes256KW:
                    return 256;
            }

            throw new NotSupportedException(ErrorMessages.FormatInvariant(ErrorMessages.NotSuportedAlgorithmForKeyWrap, Algorithm));
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
#endif