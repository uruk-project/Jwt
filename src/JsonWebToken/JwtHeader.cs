using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;

namespace JsonWebToken
{
    /// <summary>
    /// Initializes a new instance of <see cref="JwtHeader"/> which contains JSON objects 
    /// representing the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    public class JwtHeader
    {
        private static readonly JsonSerializerSettings serializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        };

        private readonly JObject _inner;

        public JwtHeader(JObject inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class. 
        /// Default string comparer <see cref="StringComparer.Ordinal"/>.
        /// </summary>
        public JwtHeader()
        {
            _inner = new JObject();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="signingKey"><see cref="JsonWebKey"/> used when creating a JWS Compact JSON.</param>
        public JwtHeader(JsonWebKey signingKey)
        {
            if (signingKey == null)
            {
                throw new ArgumentNullException(nameof(signingKey));
            }

            _inner = new JObject();
            Alg = signingKey.Alg;
            Kid = signingKey.Kid;
            SigningKey = signingKey;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtHeader"/>.
        /// <param name="encryptionKey"><see cref="JsonWebKey"/> used when creating a JWS Compact JSON.</param>
        /// <param name="encryptionAlgorithm">Algorithm used for encryption.</param>
        public JwtHeader(JsonWebKey encryptionKey, string encryptionAlgorithm)
        {
            _inner = new JObject();

            EncryptionKey = encryptionKey ?? throw new ArgumentNullException(nameof(encryptionKey));
            Enc = encryptionAlgorithm ?? throw new ArgumentNullException(nameof(encryptionAlgorithm));
            Alg = encryptionKey.Alg;
            Kid = encryptionKey.Kid;
        }

        /// <summary>
        /// Gets the <see cref="EncryptionKey"/> passed in the constructor.
        /// </summary>
        /// <remarks>This value may be null.</remarks>
        public JsonWebKey EncryptionKey { get; private set; }

        /// <summary>
        /// Gets the <see cref="SigningKey"/> passed in the constructor.
        /// </summary>
        /// <remarks>This value may be null.</remarks>
        public JsonWebKey SigningKey { get; set; }

        public JToken this[string key]
        {
            get { return _inner[key]; }
            set { _inner[key] = value; }
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        /// <remarks>If the signature algorithm is not found, null is returned.</remarks>
        public string Alg
        {
            get { return GetStandardClaim(HeaderParameterNames.Alg); }
            set { _inner[HeaderParameterNames.Alg] = value; }
        }

        /// <summary>
        /// Gets the content mime type (Cty) of the token.
        /// </summary>
        /// <remarks>If the content mime type is not found, null is returned.</remarks>
        public string Cty
        {
            get { return GetStandardClaim(HeaderParameterNames.Cty); }
            set { _inner[HeaderParameterNames.Cty] = value; }
        }

        /// <summary>
        /// Gets the encryption algorithm (Enc) of the token.
        /// </summary>
        /// <remarks>If the content mime type is not found, null is returned.</remarks>
        public string Enc
        {
            get { return GetStandardClaim(HeaderParameterNames.Enc); }
            set { _inner[HeaderParameterNames.Enc] = value; }
        }

        /// <summary>
        /// Gets the iv of symmetric key wrap.
        /// </summary>
        public string IV
        {
            get { return GetStandardClaim(HeaderParameterNames.IV); }
        }

        /// <summary>
        /// Gets the key identifier for the security key used to sign the token
        /// </summary>
        public string Kid
        {
            get { return GetStandardClaim(HeaderParameterNames.Kid); }
            set { _inner[HeaderParameterNames.Kid] = value; }
        }

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        /// <remarks>If the mime type is not found, null is returned.</remarks>
        public string Typ
        {
            get { return GetStandardClaim(HeaderParameterNames.Typ); }
            set { _inner[HeaderParameterNames.Typ] = value; }
        }

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token
        /// </summary>
        public string X5t
        {
            get { return GetStandardClaim(HeaderParameterNames.X5t); }
            set { _inner[HeaderParameterNames.X5t] = value; }
        }

        /// <summary>
        /// Encodes this instance as Base64UrlEncoded JSON.
        /// </summary>
        /// <returns>Base64UrlEncoded JSON.</returns>
        public string Base64UrlEncode()
        {
            return Base64Url.Encode(ToString());
        }

        private string GetStandardClaim(string claimType)
        {
            JToken value = null;
            if (_inner.TryGetValue(claimType, out value))
            {
                return value.Value<string>();
            }

            return null;
        }

        public bool HasHeader(string header)
        {
            return _inner.ContainsKey(header);
        }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(_inner, serializerSettings);
        }

        public static implicit operator JObject(JwtHeader header)
        {
            return header._inner;
        }
    }
}
