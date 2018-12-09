// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    public sealed class JwtHeader : Dictionary<string, object>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtHeader(Dictionary<string, object> inner)
            : base(inner)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        public JwtHeader()
            : base()
        {
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        public string Alg => GetValue<string>(HeaderParameters.Alg);

        /// <summary>
        /// Gets the content type (Cty) of the token.
        /// </summary>
        public string Cty => GetValue<string>(HeaderParameters.Cty);

        /// <summary>
        /// Gets the encryption algorithm (Enc) of the token.
        /// </summary>
        public string Enc => GetValue<string>(HeaderParameters.Enc);

        /// <summary>
        /// Gets the key identifier for the key used to sign the token.
        /// </summary>
        public string Kid => GetValue<string>(HeaderParameters.Kid);

        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        public string Typ => GetValue<string>(HeaderParameters.Typ);

        /// <summary>
        /// Gets the thumbprint of the certificate used to sign the token.
        /// </summary>
        public string X5t => GetValue<string>(HeaderParameters.X5t);

        /// <summary>
        /// Gets the URL of the JWK used to sign the token.
        /// </summary>
        public string Jku => GetValue<string>(HeaderParameters.Jku);

        /// <summary>
        /// Gets the URL of the certificate used to sign the token
        /// </summary>
        public string X5u => GetValue<string>(HeaderParameters.X5u);

        /// <summary>
        /// Gets the algorithm used to compress the token.
        /// </summary>
        public string Zip => GetValue<string>(HeaderParameters.Zip);

        /// <summary>
        /// Gets the Initialization Vector used for AES GCM encryption.
        /// </summary>
        public string IV => GetValue<string>(HeaderParameters.IV);

        /// <summary>
        /// Gets the Authentication Tag used for AES GCM encryption.
        /// </summary>
        public string Tag => GetValue<string>(HeaderParameters.Typ);

        /// <summary>
        /// Gets the Crit header.
        /// </summary>
#if NETCOREAPP3_0
        public IList<string> Crit => GetValue<List<object>>(HeaderParameters.Crit)?.Cast<string>().ToList();
#else
        public IList<string> Crit => GetValue<JArray>(HeaderParameters.Crit)?.Values<string>().ToList();
#endif

#if !NETSTANDARD
        /// <summary>
        /// Gets the ephemeral key used for ECDH key agreement.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Epk, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
#if NETCOREAPP3_0
        public ECJwk Epk => ECJwk.FromDictionary(GetValue<Dictionary<string, object>>(HeaderParameters.Epk));
#else
        public ECJwk Epk => ECJwk.FromJObject(GetValue<JObject>(HeaderParameters.Epk));
#endif

        /// <summary>
        /// Gets the Agreement PartyUInfo used for ECDH key agreement.
        /// </summary>
        public string Apu => GetValue<string>(HeaderParameters.Apu);

        /// <summary>
        /// Gets the Agreement PartyVInfo used for ECDH key agreement.
        /// </summary>
        public string Apv => GetValue<string>(HeaderParameters.Apv);
#endif

        /// <summary>
        /// Gets the header parameter for a specified key.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="key"></param>
        /// <returns></returns>
        public T GetValue<T>(string key)
        {
            if (TryGetValue(key, out var value) && value is T tValue)
            {
                return tValue;
            }

            return default;
        }
    }
}
