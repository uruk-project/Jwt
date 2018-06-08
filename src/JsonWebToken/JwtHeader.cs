using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Initializes a new instance of <see cref="JwtHeader"/> which contains JSON objects 
    /// representing the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    public class JwtHeader
    {
        public JwtHeader()
        {
        }

        ///// <summary>
        ///// Initializes a new instance of <see cref="JwtHeader"/>.
        ///// </summary>
        ///// <param name="signingKey"><see cref="JsonWebKey"/> used when creating a JWS Compact JSON.</param>
        //public JwtHeader(JsonWebKey signingKey)
        //{
        //    if (signingKey == null)
        //    {
        //        throw new ArgumentNullException(nameof(signingKey));
        //    }

        //    Alg = signingKey.Alg;
        //    Kid = signingKey.Kid;
        //    SigningKey = signingKey;
        //}

        ///// <summary>
        ///// Initializes a new instance of <see cref="JwtHeader"/>.
        ///// <param name="encryptionKey"><see cref="JsonWebKey"/> used when creating a JWS Compact JSON.</param>
        ///// <param name="encryptionAlgorithm">Algorithm used for encryption.</param>
        //public JwtHeader(JsonWebKey encryptionKey, string encryptionAlgorithm)
        //{
        //    EncryptionKey = encryptionKey ?? throw new ArgumentNullException(nameof(encryptionKey));
        //    Enc = encryptionAlgorithm ?? throw new ArgumentNullException(nameof(encryptionAlgorithm));
        //    Alg = encryptionKey.Alg;
        //    Kid = encryptionKey.Kid;
        //}

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        /// <remarks>If the signature algorithm is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameterNames.Alg)]
        public string Alg { get; set; }

        /// <summary>
        /// Gets the content mime type (Cty) of the token.
        /// </summary>
        /// <remarks>If the content mime type is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameterNames.Cty)]
        public string Cty { get; set; }

        /// <summary>
        /// Gets the encryption algorithm (Enc) of the token.
        /// </summary>
        /// <remarks>If the content mime type is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameterNames.Enc)]
        public string Enc { get; set; }

        /// <summary>
        /// Gets the key identifier for the security key used to sign the token
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameterNames.Kid)]
        public string Kid { get; set; }

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        /// <remarks>If the mime type is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameterNames.Typ)]
        public string Typ { get; set; }

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameterNames.X5t)]
        public string X5t { get; set; }

        [JsonProperty(PropertyName = HeaderParameterNames.Jku)]
        public string Jku { get; set; }

        [JsonProperty(PropertyName = HeaderParameterNames.X5u)]
        public string X5u { get; set; }

        [JsonExtensionData]
        public IDictionary<string, JToken> AdditionalData { get; set; }
    }
}
