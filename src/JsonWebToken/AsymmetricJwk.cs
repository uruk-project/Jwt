using Newtonsoft.Json;

namespace JsonWebToken
{
    public abstract class AsymmetricJwk : JsonWebKey
    {
        private string _d;

        /// <summary>
        /// Gets or sets the 'd' (ECC - Private Key OR RSA - Private Exponent).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.D, Required = Required.Default)]
        public string D
        {
            get => _d;
            private set
            {
                _d = value; 
                if (value != null)
                {
                    RawD = Base64UrlEncoder.DecodeBytes(value);
                }
            }
        }

        [JsonIgnore]
        public byte[] RawD { get; private set; }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
        [JsonIgnore]
        public abstract bool HasPrivateKey { get; }

        public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(string algorithm)
        {
            return null;
        }
    }
}
