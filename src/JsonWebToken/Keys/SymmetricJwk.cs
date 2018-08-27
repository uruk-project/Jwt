using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class SymmetricJwk : JsonWebKey
    {
        private readonly ConcurrentDictionary<SignatureAlgorithm, SymmetricSignatureProvider> _signatureProviders = new ConcurrentDictionary<SignatureAlgorithm, SymmetricSignatureProvider>();
        private readonly ConcurrentDictionary<KeyManagementAlgorithm, ConcurrentDictionary<EncryptionAlgorithm, KeyWrapProvider>> _keyWrapProviders = new ConcurrentDictionary<KeyManagementAlgorithm, ConcurrentDictionary<EncryptionAlgorithm, KeyWrapProvider>>();
        private readonly ConcurrentDictionary<EncryptionAlgorithm, AuthenticatedEncryptionProvider> _encryptionProviders = new ConcurrentDictionary<EncryptionAlgorithm, AuthenticatedEncryptionProvider>();
        private string _k;

        public SymmetricJwk(byte[] bytes)
            : this()
        {
            RawK = CloneArray(bytes);
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

        public override bool IsSupportedAlgorithm(in KeyManagementAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Symmetric && algorithm.RequiredKeySizeInBits == KeySizeInBits;
        }

        public override bool IsSupportedAlgorithm(in SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Symmetric;
        }

        public override bool IsSupportedAlgorithm(in EncryptionAlgorithm algorithm)
        {
            return algorithm.Category == EncryptionTypes.AesHmac;
        }

        public override SignatureProvider CreateSignatureProvider(in SignatureAlgorithm algorithm, bool willCreateSignatures)
        {
            if (algorithm == null)
            {
                return null;
            }

            if (_signatureProviders.TryGetValue(algorithm, out var cachedProvider))
            {
                return cachedProvider;
            }

            if (IsSupportedAlgorithm(algorithm))
            {
                var provider = new SymmetricSignatureProvider(this, algorithm);
                if (!_signatureProviders.TryAdd(algorithm, provider) && _signatureProviders.TryGetValue(algorithm, out cachedProvider))
                {
                    provider.Dispose();
                    return cachedProvider;
                }

                return provider;
            }

            return null;
        }

        public override KeyWrapProvider CreateKeyWrapProvider(in EncryptionAlgorithm encryptionAlgorithm, in KeyManagementAlgorithm contentEncryptionAlgorithm)
        {
            if (contentEncryptionAlgorithm == null)
            {
                return null;
            }

            if (_keyWrapProviders.TryGetValue(contentEncryptionAlgorithm, out var providers))
            {
                if (providers.TryGetValue(encryptionAlgorithm, out var cachedProvider))
                {
                    return cachedProvider;
                }
            }

            if (IsSupportedAlgorithm(contentEncryptionAlgorithm))
            {
                KeyWrapProvider provider;
                if (encryptionAlgorithm.Category == EncryptionTypes.AesHmac)
                {
                    provider = new AesKeyWrapProvider(this, encryptionAlgorithm, contentEncryptionAlgorithm);
                }
                else if (encryptionAlgorithm.Category == EncryptionTypes.AesGcm)
                {
                    provider = new AesGcmKeyWrapProvider(this, encryptionAlgorithm, contentEncryptionAlgorithm);
                }
                else
                {
                    return null;
                }

                if (providers == null)
                {
                    providers = new ConcurrentDictionary<EncryptionAlgorithm, KeyWrapProvider>();
                    var x = _keyWrapProviders.TryAdd(contentEncryptionAlgorithm, providers);
                }

                if (!providers.TryAdd(encryptionAlgorithm, provider) && providers.TryGetValue(encryptionAlgorithm, out var cachedProvider))
                {
                    provider.Dispose();
                    return cachedProvider;
                }

                return provider;
            }

            return null;
        }

        public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(in EncryptionAlgorithm encryptionAlgorithm)
        {
            if (_encryptionProviders.TryGetValue(encryptionAlgorithm, out var cachedProvider))
            {
                return cachedProvider;
            }

            if (IsSupportedAlgorithm(encryptionAlgorithm))
            {
                AuthenticatedEncryptionProvider provider;
                if (encryptionAlgorithm.Category == EncryptionTypes.AesHmac)
                {
                    provider = new AesCbcHmacEncryptionProvider(this, encryptionAlgorithm);
                }
                else if (encryptionAlgorithm.Category == EncryptionTypes.AesGcm)
                {
                    provider = new AesGcmEncryptionProvider(this, encryptionAlgorithm);
                }
                else
                {
                    return null;
                }
                if (!_encryptionProviders.TryAdd(encryptionAlgorithm, provider) && _encryptionProviders.TryGetValue(encryptionAlgorithm, out cachedProvider))
                {
                    (provider as IDisposable)?.Dispose();
                    return cachedProvider;
                }

                return provider;
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