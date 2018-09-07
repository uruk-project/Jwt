using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Initializes a new instance of <see cref="JwtPayload"/> which contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }.
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

        /// <summary>
        /// Gets the 'value' of the 'audience' claim { aud, 'value' } as a list of strings.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, an empty enumerable is returned.</remarks>
        [JsonConverter(typeof(AudienceConverter))]
        public IList<string> Aud { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' }.
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found OR could not be converted to <see cref="Int32"/>, null is returned.</remarks>
        [JsonConverter(typeof(EpochTimeConverter))]
        public DateTime? Exp { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, 'value' }.
        /// </summary>
        /// <remarks>If the 'JWT ID' claim is not found, null is returned.</remarks>
        public string Jti { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'Issued At' claim { iat, 'value' }.
        /// </summary>
        [JsonProperty]
        [JsonConverter(typeof(EpochTimeConverter))]
        public DateTime? Iat { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'issuer' claim is not found, null is returned.</remarks>
        public string Iss { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { nbf, 'value' }.
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found OR could not be converted to <see cref="Int32"/>, null is returned.</remarks>
        [JsonProperty]
        [JsonConverter(typeof(EpochTimeConverter))]
        public DateTime? Nbf { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'subject' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'subject' claim is not found, null is returned.</remarks>
        public string Sub { get; set; }

        [JsonExtensionData]
        public IDictionary<string, JToken> AdditionalData { get; set; } = new Dictionary<string, JToken>();
    }
}