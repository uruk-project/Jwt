using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace JsonWebToken
{
    public class SymmetricJwk : JsonWebKey
    {
        private readonly ConcurrentDictionary<string, SymmetricSignatureProvider> _signatureProviders = new ConcurrentDictionary<string, SymmetricSignatureProvider>();
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, AesKeyWrapProvider>> _keyWrapProviders = new ConcurrentDictionary<string, ConcurrentDictionary<string, AesKeyWrapProvider>>();
        private readonly ConcurrentDictionary<string, AuthenticatedEncryptionProvider> _encryptionProviders = new ConcurrentDictionary<string, AuthenticatedEncryptionProvider>();
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
            Kty = JsonWebAlgorithmsKeyTypes.Octet;
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

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    return KeySizeInBits >= 256;
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return KeySizeInBits >= 384;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return KeySizeInBits >= 512;
                case KeyManagementAlgorithms.Aes128KW:
                    return KeySizeInBits == 128;
                case KeyManagementAlgorithms.Aes192KW:
                    return KeySizeInBits == 192;
                case KeyManagementAlgorithms.Aes256KW:
                    return KeySizeInBits == 256;
                case SignatureAlgorithms.HmacSha256:
                case SignatureAlgorithms.HmacSha384:
                case SignatureAlgorithms.HmacSha512:
                    return true;
            }

            return false;
        }

        public override SignatureProvider CreateSignatureProvider(string algorithm, bool willCreateSignatures)
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

        public override KeyWrapProvider CreateKeyWrapProvider(string encryptionAlgorithm, string contentEncryptionAlgorithm)
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
                var provider = new AesKeyWrapProvider(this, encryptionAlgorithm, contentEncryptionAlgorithm);
                if (providers == null)
                {
                    providers = new ConcurrentDictionary<string, AesKeyWrapProvider>();
                    _keyWrapProviders.TryAdd(encryptionAlgorithm, providers);
                }

                if (!providers.TryAdd(contentEncryptionAlgorithm, provider) && providers.TryGetValue(encryptionAlgorithm, out var cachedProvider))
                {
                    provider.Dispose();
                    return cachedProvider;
                }

                return provider;
            }

            return null;
        }

        public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(string encryptionAlgorithm)
        {
            if (encryptionAlgorithm == null)
            {
                return null;
            }

            if (_encryptionProviders.TryGetValue(encryptionAlgorithm, out var cachedProvider))
            {
                return cachedProvider;
            }

            if (IsSupportedAuthenticatedEncryptionAlgorithm(encryptionAlgorithm))
            {
                var provider = new AuthenticatedEncryptionProvider(this, encryptionAlgorithm);
                if (!_encryptionProviders.TryAdd(encryptionAlgorithm, provider) && _encryptionProviders.TryGetValue(encryptionAlgorithm, out cachedProvider))
                {
                    provider.Dispose();
                    return cachedProvider;
                }

                return provider;
            }

            return null;
        }

        private bool IsSupportedAuthenticatedEncryptionAlgorithm(string algorithm)
        {
            if (algorithm == null)
            {
                return false;
            }

            switch (algorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return true;
            }

            return true;
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