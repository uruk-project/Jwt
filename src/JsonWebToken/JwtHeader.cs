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
        
        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        /// <remarks>If the signature algorithm is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameters.Alg)]
        public string Alg { get; set; }

        /// <summary>
        /// Gets the content mime type (Cty) of the token.
        /// </summary>
        /// <remarks>If the content mime type is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameters.Cty)]
        public string Cty { get; set; }

        /// <summary>
        /// Gets the encryption algorithm (Enc) of the token.
        /// </summary>
        /// <remarks>If the content mime type is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameters.Enc)]
        public string Enc { get; set; }

        /// <summary>
        /// Gets the key identifier for the security key used to sign the token
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Kid)]
        public string Kid { get; set; }

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        /// <remarks>If the mime type is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameters.Typ)]
        public string Typ { get; set; }

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.X5t)]
        public string X5t { get; set; }

        [JsonProperty(PropertyName = HeaderParameters.Jku)]
        public string Jku { get; set; }

        [JsonProperty(PropertyName = HeaderParameters.X5u)]
        public string X5u { get; set; }

        [JsonProperty(PropertyName = HeaderParameters.Zip)]
        public string Zip { get; set; }

        [JsonExtensionData]
        public IDictionary<string, JToken> AdditionalData { get; set; }
    }
}
