using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class SymmetricJwk : JsonWebKey
    {
        private string _k;

        public SymmetricJwk(byte[] bytes)
            : this()
        {
            RawK = CloneByteArray(bytes);
        }

        public SymmetricJwk(Span<byte> bytes)
            : this()
        {
            RawK = bytes.ToArray();
        }

        public SymmetricJwk()
        {
            Kty = JsonWebKeyTypeNames.Octet;
        }

        /// <summary>
        /// Gets or sets the 'k' (Key Value).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.K, Required = Required.Default)]
        public string K
        {
            get
            {
                if (_k == null)
                {
                    if (RawK != null && RawK.Length != 0)
                    {
                        _k = Base64Url.Encode(RawK);
                    }
                }

                return _k;
            }
            set
            {
                _k = value;
                if (value != null)
                {
                    RawK = Base64Url.Base64UrlDecode(value);
                }
            }
        }

        [JsonIgnore]
        public byte[] RawK { get; private set; }

        public override int KeySizeInBits => RawK?.Length != 0 ? RawK.Length << 3 : 0;

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes">An array of <see cref="byte"/> that contains the key in binary.</param>
        public static SymmetricJwk FromByteArray(byte[] bytes, bool computeThumbprint = true)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            var key = new SymmetricJwk(bytes);
            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint(false);
            }

            return key;
        }

        public static SymmetricJwk FromSpan(Span<byte> bytes, bool computeThumbprint = false)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            var key = new SymmetricJwk(bytes);
            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint(false);
            }

            return key;
        }

        public override bool IsSupportedAlgorithm(KeyManagementAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Symmetric && algorithm.RequiredKeySizeInBits == KeySizeInBits;
        }

        public override bool IsSupportedAlgorithm(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Symmetric;
        }

        public override bool IsSupportedAlgorithm(EncryptionAlgorithm algorithm)
        {
            return algorithm.Category == EncryptionTypes.AesHmac;
        }

        public override SignatureProvider CreateSignatureProvider(SignatureAlgorithm algorithm, bool willCreateSignatures)
        {
            if (algorithm == null)
            {
                return null;
            }

            if (IsSupportedAlgorithm(algorithm))
            {
                return new SymmetricSignatureProvider(this, algorithm);
            }

            return null;
        }

        public override KeyWrapProvider CreateKeyWrapProvider(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (contentEncryptionAlgorithm == null)
            {
                return null;
            }
            
            if (IsSupportedAlgorithm(contentEncryptionAlgorithm))
            {
                switch (encryptionAlgorithm.Category)
                {
                    case EncryptionTypes.AesHmac:
                        return new AesKeyWrapProvider(this, encryptionAlgorithm, contentEncryptionAlgorithm);
                    case EncryptionTypes.AesGcm:
                        return new AesGcmKeyWrapProvider(this, encryptionAlgorithm, contentEncryptionAlgorithm);
                    default:
                        return null;
                }              
            }

            return null;
        }

        public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (IsSupportedAlgorithm(encryptionAlgorithm))
            {
                switch (encryptionAlgorithm.Category)
                {
                    case EncryptionTypes.None:
                        break;
                    case EncryptionTypes.AesHmac:
                        return new AesCbcHmacEncryptionProvider(this, encryptionAlgorithm);
                    case EncryptionTypes.AesGcm:
                        return new AesGcmEncryptionProvider(this, encryptionAlgorithm);
                    default:
                        return null;
                }
            }

            return null;
        }

        public static SymmetricJwk FromBase64Url(string k, bool computeThumbprint = true)
        {
            if (k == null)
            {
                throw new ArgumentNullException(nameof(k));
            }

            var key = new SymmetricJwk()
            {
                K = k
            };

            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint(false);
            }

            return key;
        }

        public static SymmetricJwk GenerateKey(int sizeInBits, string algorithm = null)
        {
            var key = FromByteArray(GenerateKeyBytes(sizeInBits), false);
            key.Alg = algorithm;
            return key;
        }

        private static byte[] GenerateKeyBytes(int sizeInBits)
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[sizeInBits >> 3];
                rnd.GetBytes(key);

                return key;
            }
        }

        /// <summary>
        ///  Creates a minimal representation of the current key.
        /// </summary>
        /// <returns></returns>
        public override JsonWebKey ExcludeOptionalMembers()
        {
            return new SymmetricJwk(RawK);
        }

        public override byte[] ToByteArray()
        {
            return RawK;
        }
    }
}