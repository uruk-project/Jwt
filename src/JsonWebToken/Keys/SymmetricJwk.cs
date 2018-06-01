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
            RawK = CloneArray(bytes);
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
                    RawK = Base64Url.DecodeBytes(value);
                }
            }
        }

        [JsonIgnore]
        public byte[] RawK { get; private set; }

        public override int KeySize => RawK?.Length != 0 ? RawK.Length << 3 : 0;

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes">An array of <see cref="byte"/> that contains the key in binary.</param>
        public static SymmetricJwk FromByteArray(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            var key = new SymmetricJwk(bytes);
            key.Kid = key.ComputeThumbprint();
            return key;
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case ContentEncryptionAlgorithms.Aes128CbcHmacSha256:
                    return KeySize >= 256;
                case ContentEncryptionAlgorithms.Aes192CbcHmacSha384:
                    return KeySize >= 384;
                case ContentEncryptionAlgorithms.Aes256CbcHmacSha512:
                    return KeySize >= 512;
                case KeyManagementAlgorithms.Aes128KW:
                    return KeySize == 128;
                case KeyManagementAlgorithms.Aes192KW:
                    return KeySize == 192;
                case KeyManagementAlgorithms.Aes256KW:
                    return KeySize == 256;
                case SignatureAlgorithms.HmacSha256:
                case SignatureAlgorithms.HmacSha384:
                case SignatureAlgorithms.HmacSha512:
                    return true;
            }

            return false;
        }

        public override SignatureProvider CreateSignatureProvider(string algorithm, bool willCreateSignatures)
        {
            if (IsSupportedAlgorithm(algorithm))
            {
                return new SymmetricSignatureProvider(this, algorithm);
            }

            return null;
        }

        public override KeyWrapProvider CreateKeyWrapProvider(string algorithm)
        {
            if (IsSupportedAlgorithm(algorithm))
            {
                return new SymmetricKeyWrapProvider(this, algorithm);
            }

            return null;
        }

        private bool IsSupportedAuthenticatedEncryptionAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
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

        public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(string algorithm)
        {
            if (IsSupportedAuthenticatedEncryptionAlgorithm(algorithm))
            {
                return new AuthenticatedEncryptionProvider(this, algorithm);
            }

            return null;
        }

        public static SymmetricJwk GenerateKey(int sizeInBits, string algorithm = null)
        {
            var key = FromByteArray(GenerateKeyBytes(sizeInBits));
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
        public override JsonWebKey CloneMinimal()
        {
            return new SymmetricJwk(RawK);
        }
    }
}
