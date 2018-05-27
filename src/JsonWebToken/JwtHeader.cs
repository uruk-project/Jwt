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
        private readonly JObject _inner;

        public JwtHeader(JObject inner)
        {

            _inner = inner;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class. 
        /// Default string comparer <see cref="StringComparer.Ordinal"/>.
        /// </summary>
        public JwtHeader()
            : this((JsonWebKey)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="signingKey"><see cref="JsonWebKey"/> used when creating a JWS Compact JSON.</param>
        public JwtHeader(JsonWebKey signingKey)
        {
            _inner = new JObject();

            if (signingKey == null)
            {
                Alg = SecurityAlgorithms.None;
            }
            else
            {
                Alg = signingKey.Alg;
                Kid = signingKey.Kid;
            }

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
            get
            {
                return _inner[key];
            }

            set
            {
                _inner[key] = value;
            }
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        /// <remarks>If the signature algorithm is not found, null is returned.</remarks>
        public string Alg
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.Alg);
            }

            set
            {
                _inner[JwtHeaderParameterNames.Alg] = value;
            }
        }

        /// <summary>
        /// Gets the content mime type (Cty) of the token.
        /// </summary>
        /// <remarks>If the content mime type is not found, null is returned.</remarks>
        public string Cty
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.Cty);
            }

            set
            {
                _inner[JwtHeaderParameterNames.Cty] = value;
            }
        }

        /// <summary>
        /// Gets the encryption algorithm (Enc) of the token.
        /// </summary>
        /// <remarks>If the content mime type is not found, null is returned.</remarks>
        public string Enc
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.Enc);
            }

            set
            {
                _inner[JwtHeaderParameterNames.Enc] = value;
            }
        }

        /// <summary>
        /// Gets the iv of symmetric key wrap.
        /// </summary>
        public string IV
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.IV);
            }
        }

        /// <summary>
        /// Gets the key identifier for the security key used to sign the token
        /// </summary>
        public string Kid
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.Kid);
            }

            set
            {
                _inner[JwtHeaderParameterNames.Kid] = value;
            }
        }

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        /// <remarks>If the mime type is not found, null is returned.</remarks>
        public string Typ
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.Typ);
            }

            set
            {
                _inner[JwtHeaderParameterNames.Typ] = value;
            }
        }

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token
        /// </summary>
        public string X5t
        {
            get
            {
                return GetStandardClaim(JwtHeaderParameterNames.X5t);
            }

            set
            {
                _inner[JwtHeaderParameterNames.X5t] = value;
            }
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

        public override string ToString()
        {
            return _inner.ToString(Formatting.None);
        }

        public static implicit operator JObject(JwtHeader header)
        {
            return header._inner;
        }
    }
}
