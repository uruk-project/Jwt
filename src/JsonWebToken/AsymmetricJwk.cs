// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;

namespace JsonWebToken
{
    /// <summary>
    /// Represents an asymmetric JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public abstract class AsymmetricJwk : Jwk
    {
        private string _d;

        protected AsymmetricJwk()
        {
        }

        /// <summary>
        /// Gets or sets the 'd' (ECC - Private Key OR RSA - Private Exponent).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JwkParameterNames.D, Required = Required.Default)]
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

        /// <inheritsdoc/>
        public override AuthenticatedEncryptor CreateAuthenticatedEncryptor(EncryptionAlgorithm algorithm)
        {
            return null;
        }
    }
}
