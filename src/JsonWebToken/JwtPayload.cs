using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Initializes a new instance of <see cref="JwtPayload"/> which contains JSON objects representing the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }.
    /// </summary>
    public class JwtPayload
    {
        private static readonly JsonSerializerSettings serializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        };

        private readonly JObject _inner;

        public JwtPayload(string plaintext) 
            : this()
        {
            Plaintext = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
        }

        public JwtPayload(JObject inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class with no claims. . 
        /// Creates a empty <see cref="JwtPayload"/>
        /// </summary>
        public JwtPayload()
            : this(new JObject())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtPayload"/> class with claims added for each parameter specified. 
        /// </summary>
        public JwtPayload(IEnumerable<JProperty> claims)
            : this()
        {
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            AddClaims(claims);
        }

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

        public IEnumerable<JProperty> Properties => _inner.Properties();

        /// <summary>
        /// Gets the 'value' of the 'acr' claim { acr, 'value' }.
        /// </summary>
        /// <remarks>If the 'acr' claim is not found, null is returned.</remarks>
        public string Acr
        {
            get
            {
                return GetStandardClaim(ClaimNames.Acr);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'amr' claim { amr, 'value' } as list of strings.
        /// </summary>
        /// <remarks>If the 'amr' claim is not found, an empty enumerable is returned.</remarks>
        public IList<string> Amr
        {
            get
            {
                return GetIListClaims(ClaimNames.Amr);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'auth_time' claim { auth_time, 'value' }.
        /// </summary>
        /// <remarks>If the 'auth_time' claim is not found OR could not be converted to <see cref="Int32"/>, null is returned.</remarks>
        public int? AuthTime
        {
            get
            {
                return GetIntClaim(ClaimNames.AuthTime);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'audience' claim { aud, 'value' } as a list of strings.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, an empty enumerable is returned.</remarks>
        public IList<string> Aud
        {
            get
            {
                return GetIListClaims(ClaimNames.Aud);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'azp' claim { azp, 'value' }.
        /// </summary>
        /// <remarks>If the 'azp' claim is not found, null is returned.</remarks>
        public string Azp
        {
            get
            {
                return GetStandardClaim(ClaimNames.Azp);
            }
        }

        /// <summary>
        /// Gets 'value' of the 'c_hash' claim { c_hash, 'value' }.
        /// </summary>
        /// <remarks>If the 'c_hash' claim is not found, null is returned.</remarks>
        public string CHash
        {
            get
            {
                return GetStandardClaim(ClaimNames.CHash);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' }.
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found OR could not be converted to <see cref="Int32"/>, null is returned.</remarks>
        public int? Exp
        {
            get { return GetIntClaim(ClaimNames.Exp); }
        }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, 'value' }.
        /// </summary>
        /// <remarks>If the 'JWT ID' claim is not found, null is returned.</remarks>
        public string Jti
        {
            get
            {
                return GetStandardClaim(ClaimNames.Jti);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'Issued At' claim { iat, 'value' }.
        /// </summary>
        public DateTime? Iat
        {
            get { return GetDateTime(ClaimNames.Iat); }
        }

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        /// <remarks>If the 'issuer' claim is not found, null is returned.</remarks>
        public string Iss
        {
            get
            {
                return GetStandardClaim(ClaimNames.Iss);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { nbf, 'value' }.
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found OR could not be converted to <see cref="Int32"/>, null is returned.</remarks>
        public int? Nbf
        {
            get { return GetIntClaim(ClaimNames.Nbf); }
        }

        /// <summary>
        /// Gets the 'value' of the 'nonce' claim { nonce, 'value' }.
        /// </summary>
        /// <remarks>If the 'nonce' claim is not found, null is returned.</remarks>
        public string Nonce
        {
            get
            {
                return GetStandardClaim(ClaimNames.Nonce);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'subject' claim { sub, 'value' }.
        /// </summary>
        /// <remarks>If the 'subject' claim is not found, null is returned.</remarks>
        public string Sub
        {
            get
            {
                return GetStandardClaim(ClaimNames.Sub);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned. Time is returned as UTC.</remarks>
        public DateTime? NotBefore
        {
            get
            {
                return GetDateTime(ClaimNames.Nbf);
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? Expires
        {
            get
            {
                return GetDateTime(ClaimNames.Exp);
            }
        }

        public string Plaintext { get; }

        /// <summary>
        /// Adds a JSON object representing the <see cref="JToken"/> to the <see cref="JwtPayload"/>
        /// </summary>
        public void AddClaim(JProperty claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var current = this[claim.Name];
            if (current != null)
            {
                this[claim.Name] = new JArray(current, claim.Value);
            }
            else
            {
                this[claim.Name] = claim.Value;
            }
        }

        /// <summary>
        /// Adds a number of <see cref="JToken"/> to the <see cref="JwtPayload"/> as JSON { name, value } pairs.
        /// </summary>
        public void AddClaims(IEnumerable<JProperty> claims)
        {
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            foreach (JProperty claim in claims)
            {
                if (claim == null)
                {
                    continue;
                }

                AddClaim(claim);
            }
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

        private int? GetIntClaim(string claimType)
        {
            JToken value;
            if (_inner.TryGetValue(claimType, out value))
            {
                return value.Value<int?>();
            }

            return null;
        }

        private IList<string> GetIListClaims(string claimType)
        {
            JToken value = null;
            if (_inner.TryGetValue(claimType, out value))
            {
                if (value.Type == JTokenType.Array)
                {
                    return new List<string>(value.Values<string>());
                }

                return new List<string>(new[] { value.Value<string>() });
            }

            return null;
        }

        private DateTime? GetDateTime(string key)
        {
            JToken dateValue;
            if (!_inner.TryGetValue(key, out dateValue) || !dateValue.HasValues)
            {
                return default(DateTime?);
            }

            return EpochTime.ToDateTime(dateValue.Value<long>());
        }

        public override string ToString()
        {
            return _inner.Count != 0 ? JsonConvert.SerializeObject(_inner, serializerSettings) : Plaintext ?? string.Empty;
        }

        public static implicit operator JObject(JwtPayload payload)
        {
            return payload._inner;
        }
    }
}
