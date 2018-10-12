using Newtonsoft.Json;
using System;
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
                        _k = Base64Url.Base64UrlEncode(RawK);
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

        public static SymmetricJwk FromByteArray(byte[] bytes) => FromByteArray(bytes, computeThumbprint: false);

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes">An array of <see cref="byte"/> that contains the key in binary.</param>
        public static SymmetricJwk FromByteArray(byte[] bytes, bool computeThumbprint)
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

        public static SymmetricJwk FromSpan(Span<byte> bytes) => FromSpan(bytes, computeThumbprint: false);

        public static SymmetricJwk FromSpan(Span<byte> bytes, bool computeThumbprint)
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

        public override bool IsSupported(KeyManagementAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Symmetric && algorithm.RequiredKeySizeInBits == KeySizeInBits;
        }

        public override bool IsSupported(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Symmetric;
        }

        public override bool IsSupported(EncryptionAlgorithm algorithm)
        {
            return algorithm.Category == EncryptionTypes.AesHmac;
        }

        public override Signer CreateSigner(SignatureAlgorithm algorithm, bool willCreateSignatures)
        {
            if (algorithm == null)
            {
                return null;
            }

            if (IsSupported(algorithm))
            {
                return new SymmetricSigner(this, algorithm);
            }

            return null;
        }

        public override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (contentEncryptionAlgorithm == null)
            {
                return null;
            }

            if (IsSupported(contentEncryptionAlgorithm))
            {
                switch (encryptionAlgorithm.Category)
                {
                    case EncryptionTypes.AesHmac:
                        return new AesKeyWrapper(this, encryptionAlgorithm, contentEncryptionAlgorithm);
                    case EncryptionTypes.AesGcm:
                        return new AesGcmKeyWrapper(this, encryptionAlgorithm, contentEncryptionAlgorithm);
                    default:
                        return null;
                }
            }

            return null;
        }

        public override AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm encryptionAlgorithm)
        {
            if (IsSupported(encryptionAlgorithm))
            {
                switch (encryptionAlgorithm.Category)
                {
                    case EncryptionTypes.None:
                        break;
                    case EncryptionTypes.AesHmac:
                        return new AesCbcHmacEncryptor(this, encryptionAlgorithm);
                    case EncryptionTypes.AesGcm:
                        return new AesGcmEncryptor(this, encryptionAlgorithm);
                    default:
                        return null;
                }
            }

            return null;
        }

        public static SymmetricJwk FromBase64Url(string k) => FromBase64Url(k, computeThumbprint: false);

        public static SymmetricJwk FromBase64Url(string k, bool computeThumbprint)
        {
            if (k == null)
            {
                throw new ArgumentNullException(nameof(k));
            }

            var key = new SymmetricJwk
            {
                K = k
            };

            if (computeThumbprint)
            {
                key.Kid = key.ComputeThumbprint(false);
            }

            return key;
        }

        public static SymmetricJwk GenerateKey(int sizeInBits) => GenerateKey(sizeInBits, algorithm: null);

        public static SymmetricJwk GenerateKey(int sizeInBits, string algorithm)
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
        public override JsonWebKey Normalize()
        {
            return new SymmetricJwk(RawK);
        }

        public override byte[] ToByteArray()
        {
            return RawK;
        }
    }
}