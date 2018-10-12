using JsonWebToken.Internal;
using Newtonsoft.Json;

namespace JsonWebToken
{
    public abstract class AsymmetricJwk : JsonWebKey
    {
        private string _d;

        protected AsymmetricJwk()
        {
        }

        /// <summary>
        /// Gets or sets the 'd' (ECC - Private Key OR RSA - Private Exponent).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.D, Required = Required.Default)]
        public string D
        {
            get
            {
                if (_d == null)
                {
                    if (RawD != null && RawD.Length != 0)
                    {
                        _d = Base64Url.Base64UrlEncode(RawD);
                    }
                }

                return _d;
            }

            set
            {
                _d = value;
                if (value != null)
                {
                    RawD = Base64Url.Base64UrlDecode(value);
                }
            }
        }

        [JsonIgnore]
        public byte[] RawD { get; protected set; }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        [JsonIgnore]
        public abstract bool HasPrivateKey { get; }

        public override AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm algorithm)
        {
            return null;
        }
    }
}
