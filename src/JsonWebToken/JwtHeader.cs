using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    public sealed class JwtHeader
    {
        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        /// <remarks>If the signature algorithm is not found, null is returned.</remarks>
        [JsonProperty(PropertyName = HeaderParameters.Alg, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Alg { get; set; }

        /// <summary>
        /// Gets the content type (Cty) of the token.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Cty, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Cty { get; set; }

        /// <summary>
        /// Gets the encryption algorithm (Enc) of the token.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Enc, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Enc { get; set; }

        /// <summary>
        /// Gets the key identifier for the key used to sign the token.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Kid, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Kid { get; set; }

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Typ, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Typ { get; set; }

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.X5t, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string X5t { get; set; }
        
        /// <summary>
        /// Gets the URL of the JWK used to sign the token.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Jku, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Jku { get; set; }

        /// <summary>
        /// Gets the URL of the certificate used to sign the token
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.X5u, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string X5u { get; set; }
        
        /// <summary>
        /// Gets the algorithm used to compress the token.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Zip, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Zip { get; set; }
        
        /// <summary>
        /// Gets the Initialization Vector used for AES GCM encryption.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.IV, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string IV { get; set; }

        /// <summary>
        /// Gets the Authentication Tag used for AES GCM encryption.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Tag, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Tag { get; set; }

#if NETCOREAPP2_1
        /// <summary>
        /// Gets the ephemeral key used for ECDH key agreement.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Epk, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public ECJwk Epk { get; set; }

        /// <summary>
        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Apu, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Apu { get; set; }

        /// <summary>
        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Apv, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public string Apv { get; set; }
#endif

        [JsonExtensionData]
        public IDictionary<string, JToken> AdditionalData { get; set; }
    }
}
