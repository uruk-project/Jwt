using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// Contains some information which used to create a token.
    /// </summary>
    public class JsonWebTokenDescriptor
    {
        public JsonWebTokenDescriptor()
            : this((JObject)null, null)
        {
        }

        public JsonWebTokenDescriptor(string payloadJson, string headerJson)
            : this(JObject.Parse(payloadJson), JObject.Parse(headerJson))
        {
        }

        public JsonWebTokenDescriptor(string jsonPayload)
            : this(JObject.Parse(jsonPayload))
        {
        }

        public JsonWebTokenDescriptor(JObject payload)
            : this(payload, null)
        {
        }

        public JsonWebTokenDescriptor(JObject payload, JObject header)
        {
            Payload = payload ?? new JObject();
            Header = header ?? new JObject();
        }

        public JObject Payload { get; private set; }

        public JObject Header { get; private set; }

        /// <summary>
        /// Gets or sets the value of the 'jti' claim.
        /// </summary>
        public string Id
        {
            get { return GetStringClaim(JwtRegisteredClaimNames.Jti); }
            set { SetClaim(JwtRegisteredClaimNames.Jti, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public string Audience
        {
            get { return GetStringClaim(JwtRegisteredClaimNames.Aud); }
            set { SetClaim(JwtRegisteredClaimNames.Aud, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'aud' claim.
        /// </summary>
        public ICollection<string> Audiences
        {
            get { return GetListClaims(JwtRegisteredClaimNames.Aud); }
            set { SetClaim(JwtRegisteredClaimNames.Aud, value); }
        }

        /// <summary>
        /// Gets or sets the value of the 'exp' claim.
        /// </summary>
        public DateTime? Expires
        {
            get { return GetDateTime(JwtRegisteredClaimNames.Exp); }
            set { SetClaim(JwtRegisteredClaimNames.Exp, value); }
        }

        /// <summary>
        /// Gets or sets the issuer of this <see cref="JsonWebTokenDescriptor"/>.
        /// </summary>
        public string Issuer
        {
            get { return GetStringClaim(JwtRegisteredClaimNames.Iss); }
            set { SetClaim(JwtRegisteredClaimNames.Iss, value); }
        }

        /// <summary>
        /// Gets or sets the time the security token was issued.
        /// </summary>
        public DateTime? IssuedAt
        {
            get { return GetDateTime(JwtRegisteredClaimNames.Iat); }
            set { SetClaim(JwtRegisteredClaimNames.Iat, value); }
        }

        /// <summary>
        /// Gets or sets the notbefore time for the security token.
        /// </summary>
        public DateTime? NotBefore
        {
            get { return GetDateTime(JwtRegisteredClaimNames.Nbf); }
            set { SetClaim(JwtRegisteredClaimNames.Nbf, value); }
        }

        /// <summary>
        /// Gets or sets the <see cref="SigningKey"/> used to create a security token.
        /// </summary>
        public JsonWebKey SigningKey { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="EncryptingKey"/> used to create a encrypted security token.
        /// </summary>
        public JsonWebKey EncryptingKey { get; set; }

        /// <summary>
        /// Reprensents the 'enc' header for a JWE.
        /// </summary>
        public string EncryptionAlgorithm { get; set; }
        
        /// <summary>
        /// Reprensents the 'alg' header for a JWE.
        /// </summary>
        public string ContentEncryptionAlgorithm { get; set; }

        public void AddClaim(string name, string value)
        {
            SetClaim(name, value);
        }

        public void AddClaim(string name, DateTime? value)
        {
            SetClaim(name, value);
        }

        public void AddClaim(string name, int value)
        {
            Payload[name] = value;
        }

        public void AddClaim(string name, bool value)
        {
            Payload[name] = value;
        }

        public void AddClaim(string name, JObject value)
        {
            Payload[name] = value;
        }

        public void AddClaim(string name, JValue value)
        {
            Payload[name] = value;
        }

        public void AddClaim(string name, JArray value)
        {
            Payload[name] = value;
        }

        private string GetStringClaim(string claimType)
        {
            JToken value = null;
            if (Payload.TryGetValue(claimType, out value))
            {
                return value.Value<string>();
            }

            return null;
        }

        private void SetClaim(string claimType, string value)
        {
            Payload[claimType] = value;
        }

        internal int? GetIntClaim(string claimType)
        {
            JToken value;
            if (Payload.TryGetValue(claimType, out value))
            {
                return value.Value<int?>();
            }

            return null;
        }

        private IList<string> GetListClaims(string claimType)
        {
            JToken value = null;
            if (Payload.TryGetValue(claimType, out value))
            {
                if (value.Type == JTokenType.Array)
                {
                    return new List<string>(value.Values<string>());
                }

                return new List<string>(new[] { value.Value<string>() });
            }

            return null;
        }


        private void SetClaim(string claimType, ICollection<string> value)
        {
            Payload[claimType] = JArray.FromObject(value);
        }

        private DateTime? GetDateTime(string key)
        {
            JToken dateValue;
            if (!Payload.TryGetValue(key, out dateValue))
            {
                return null;
            }

            return EpochTime.ToDateTime(dateValue.Value<int>());
        }


        private void SetClaim(string claimType, DateTime? value)
        {
            if (value.HasValue)
            {
                Payload[claimType] = EpochTime.GetIntDate(value.Value);
            }
            else
            {
                Payload[claimType] = null;
            }
        }
    }
}
