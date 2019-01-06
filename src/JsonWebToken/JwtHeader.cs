// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the cryptographic operations applied to the JWT and optionally 
    /// any additional properties of the JWT. 
    /// </summary>
    public sealed class JwtHeader
    {
        private readonly Dictionary<string, object> _inner;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        /// <param name="inner"></param>
        public JwtHeader(Dictionary<string, object> inner)
        {
            _inner = inner;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtHeader"/> class.
        /// </summary>
        public JwtHeader()
        {
            _inner = new Dictionary<string, object>();
        }

        /// <summary>
        /// Gets the signature algorithm that was used to create the signature.
        /// </summary>
        public string Alg { get; set; }
     
        /// <summary>
        /// Gets the content type (Cty) of the token.
        /// </summary>
        public string Cty { get; set; }

        /// <summary>
        /// Gets the encryption algorithm (Enc) of the token.
        /// </summary>
        public string Enc { get; set; }
        
        /// <summary>
        /// Gets the key identifier for the key used to sign the token.
        /// </summary>
        public string Kid { get; set; }
     
        /// <summary>
        /// Gets the mime type (Typ) of the token.
        /// </summary>
        public string Typ { get; set; }

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
        public string Zip { get; set; }
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
        public IList<string> Crit { get; set; }

#if !NETSTANDARD
        /// <summary>
        /// Gets the ephemeral key used for ECDH key agreement.
        /// </summary>
        [JsonProperty(PropertyName = HeaderParameters.Epk, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore)]
        public ECJwk Epk => ECJwk.FromDictionary(GetValue<Dictionary<string, object>>(HeaderParameters.Epk));

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
            if (_inner.TryGetValue(key, out var value) && value is T tValue)
            {
                return tValue;
            }

            return default;
        }

        /// <summary>
        ///  Gets the claim for a specified key in the current <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public object this[string key]
        {
            get
            {
                switch (key)
                {
                    case HeaderParameters.Alg:
                        return Alg;
                    case HeaderParameters.Enc:
                        return Enc;
                    case HeaderParameters.Kid:
                        return Kid;
                    case HeaderParameters.Cty:
                        return Cty;
                    case HeaderParameters.Typ:
                        return Typ;
                    case HeaderParameters.Zip:
                        return Zip;
                    case HeaderParameters.Crit:
                        return Crit;
                    default:
                        return _inner.TryGetValue(key, out var value) ? value : null;
                }
            }

            set
            {
                switch (key)
                {
                    case HeaderParameters.Alg:
                        Alg = (string)value;
                        break;
                    case HeaderParameters.Enc:
                        Enc = (string)value;
                        break;
                    case HeaderParameters.Kid:
                        Kid = (string)value;
                        break;
                    case HeaderParameters.Cty:
                        Cty = (string)value;
                        break;
                    case HeaderParameters.Typ:
                        Typ = (string)value;
                        break;
                    case HeaderParameters.Zip:
                        Zip = (string)value;
                        break;
                    case HeaderParameters.Crit:
                        Crit = (IList<string>)value;
                        break;
                    default:
                        _inner[key] = value;
                        break;
                }
            }
        }

        /// <summary>
        /// Determines whether the <see cref="JwtHeader"/> contains the specified key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public bool ContainsKey(string key)
        {
            return _inner.ContainsKey(key);
        }
    }
}
