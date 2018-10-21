// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the claims contained in the JWT.
    /// </summary>
    public sealed class JwtPayload
    {
        public JToken this[string key]
        {
            get
            {
                if (TryGetValue(key, out var value))
                {
                    return value;
                }

                return null;
            }
        }

        /// <summary>
        /// Gets the 'audience' claim as a list of strings.
        /// </summary>
        [JsonConverter(typeof(AudienceConverter))]
        public IList<string> Aud { get; set; }

        /// <summary>
        /// Gets the 'expiration time' claim.
        /// </summary>
        [JsonConverter(typeof(EpochTimeConverter))]
        public DateTime? Exp { get; set; }

        /// <summary>
        /// Gets the 'JWT ID' claim.
        /// </summary>
        public string Jti { get; set; }

        /// <summary>
        /// Gets the 'issued at' claim.
        /// </summary>
        [JsonProperty]
        [JsonConverter(typeof(EpochTimeConverter))]
        public DateTime? Iat { get; set; }

        /// <summary>
        /// Gets the 'issuer' claim.
        /// </summary>
        public string Iss { get; set; }

        /// <summary>
        /// Gets the 'not before' claim.
        /// </summary>
        [JsonProperty]
        [JsonConverter(typeof(EpochTimeConverter))]
        public DateTime? Nbf { get; set; }

        /// <summary>
        /// Gets the 'subject' claim.
        /// </summary>
        public string Sub { get; set; }

        [JsonExtensionData]
        public IDictionary<string, JToken> AdditionalData { get; set; } = new Dictionary<string, JToken>();

        public bool TryGetValue(string key, out JToken value)
        {
            switch (key)
            {
                case Claims.Aud:
                    value = Aud == null ? null : new JValue(Aud);
                    return true;
                case Claims.Exp:
                    value = Exp.HasValue ? new JValue(Exp.Value) : null;
                    return true;
                case Claims.Iat:
                    value = Iat.HasValue ? new JValue(Iat.Value) : null;
                    return true;
                case Claims.Iss:
                    value = Iss == null ? null : new JValue(Iss);
                    return true;
                case Claims.Nbf:
                    value = Nbf.HasValue ? new JValue(Nbf.HasValue) : null;
                    return true;
                case Claims.Sub:
                    value = Sub == null ? null : new JValue(Sub);
                    return true;
                default:
                    return AdditionalData.TryGetValue(key, out value);
            }
        }
    }
}