using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Text;

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
            if (encryptionKey == null)
            {
                throw new ArgumentNullException(nameof(encryptionKey));
            }

            if (encryptionAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(encryptionAlgorithm));
            }

            Alg = encryptionKey.Alg;
            Enc = encryptionAlgorithm;
            Kid = encryptionKey.Kid;
            EncryptionKey = encryptionKey;
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

            private set
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

            private set
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

            private set
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

            private set
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

            private set
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
        }

        /// <summary>
        /// Deserializes Base64UrlEncoded JSON into a <see cref="JwtHeader"/> instance.
        /// </summary>
        /// <param name="base64UrlEncodedJsonString">Base64url encoded JSON to deserialize.</param>
        /// <returns>An instance of <see cref="JwtHeader"/>.</returns>
        public static JwtHeader Base64UrlDeserialize(string base64UrlEncodedJsonString)
        {
            return Deserialize(Base64UrlEncoder.Decode(base64UrlEncodedJsonString));
        }
        public static JwtHeader Base64UrlDeserialize(ReadOnlySpan<char> base64UrlEncodedJsonString)
        {
            return Deserialize(Encoding.UTF8.GetString(Base64UrlEncoder.Base64UrlDecode(base64UrlEncodedJsonString)));
        }

        /// <summary>
        /// Encodes this instance as Base64UrlEncoded JSON.
        /// </summary>
        /// <returns>Base64UrlEncoded JSON.</returns>
        public string Base64UrlEncode()
        {
            return Base64UrlEncoder.Encode(SerializeToJson());
        }

        public bool TryBase64UrlEncode(Span<byte> destination, out int bytesWritten)
        {
            var status = Base64UrlEncoder.Base64UrlEncode(Encoding.UTF8.GetBytes(SerializeToJson()), destination, out int bytesConsumed, out bytesWritten);
            return status == OperationStatus.Done;
        }

        /// <summary>
        /// Deserialzes JSON into a <see cref="JwtHeader"/> instance.
        /// </summary>
        /// <param name="jsonString"> The JSON to deserialize.</param>
        /// <returns>An instance of <see cref="JwtHeader"/>.</returns>
        public static JwtHeader Deserialize(string jsonString)
        {
            return new JwtHeader(JObject.Parse(jsonString));
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

        /// <summary>
        /// Serializes this instance to JSON.
        /// </summary>
        /// <returns>This instance as JSON.</returns>
        /// <remarks>Use <see cref="JsonExtensions.Serializer"/> to customize JSON serialization.</remarks>
        public string SerializeToJson()
        {
            return _inner.ToString(Formatting.None);
        }
    }
}
