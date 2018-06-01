using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class IdTokenDescriptor : JwsDescriptor
    {
        private static readonly IReadOnlyDictionary<string, JTokenType[]> IdTokenRequiredClaims = new Dictionary<string, JTokenType[]>
        {
            { ClaimNames.Iss, new [] { JTokenType.String} },
            { ClaimNames.Sub, new [] { JTokenType.String} },
            { ClaimNames.Aud, new [] { JTokenType.String, JTokenType.Array} },
            { ClaimNames.Exp, new [] { JTokenType.Integer } },
            { ClaimNames.Iat, new [] { JTokenType.Integer } }
        };
        private static readonly IReadOnlyDictionary<string, JTokenType[]> IdTokenRequiredClaimsImplicit = new Dictionary<string, JTokenType[]>
        {
            { ClaimNames.Iss, new [] { JTokenType.String} },
            { ClaimNames.Sub, new [] { JTokenType.String} },
            { ClaimNames.Aud, new [] { JTokenType.String, JTokenType.Array} },
            { ClaimNames.Exp, new [] { JTokenType.Integer } },
            { ClaimNames.Iat, new [] { JTokenType.Integer } },
            { ClaimNames.Nonce, new [] { JTokenType.String} },
            { ClaimNames.AtHash, new [] { JTokenType.String } }
        };
        private static readonly IReadOnlyDictionary<string, JTokenType[]> IdTokenRequiredClaimsHybrid = new Dictionary<string, JTokenType[]>
        {
            { ClaimNames.Iss, new [] { JTokenType.String } },
            { ClaimNames.Sub, new [] { JTokenType.String } },
            { ClaimNames.Aud, new [] { JTokenType.String, JTokenType.Array} },
            { ClaimNames.Exp, new [] { JTokenType.Integer } },
            { ClaimNames.Iat, new [] { JTokenType.Integer } },
            { ClaimNames.Nonce, new [] { JTokenType.String } },
            { ClaimNames.AtHash, new [] { JTokenType.String } },
            { ClaimNames.CHash, new [] { JTokenType.String } }
        };

        public IdTokenDescriptor()
        {
        }

        public IdTokenDescriptor(JObject payload)
            :base (payload)
        {
        }

        public OpenIdConnectFlow Flow { get; set; }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public DateTime? AuthenticationTime
        {
            get { return GetDateTime(ClaimNames.AuthTime); }
            set { AddClaim(ClaimNames.AuthTime, value); }
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nonce
        {
            get { return GetStringClaim(ClaimNames.Nonce); }
            set { AddClaim(ClaimNames.Nonce, value); }
        }

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string AuthenticationContextClassReference
        {
            get { return GetStringClaim(ClaimNames.Acr); }
            set { AddClaim(ClaimNames.Acr, value); }
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public IReadOnlyList<string> AuthenticationMethodsReferences
        {
            get { return GetListClaims(ClaimNames.AuthTime); }
            set { SetClaim(ClaimNames.AuthTime, value); }
        }

        public void AddAuthenticationMethodsReferences(string acr)
        {
            AddClaim(ClaimNames.Acr, acr);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AuthorizedParty
        {
            get { return GetStringClaim(ClaimNames.AuthTime); }
            set { AddClaim(ClaimNames.AuthTime, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AccessTokenHash
        {
            get { return GetStringClaim(ClaimNames.AtHash); }
            set { AddClaim(ClaimNames.AtHash, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string CodeHash
        {
            get { return GetStringClaim(ClaimNames.CHash); }
            set { AddClaim(ClaimNames.AuthTime, value); }
        }

        protected override IReadOnlyDictionary<string, JTokenType[]> RequiredClaims
        {
            get
            {
                switch (Flow)
                {
                    case OpenIdConnectFlow.AuthorizationCode:
                        return IdTokenRequiredClaims;
                    case OpenIdConnectFlow.Implicit:
                        return IdTokenRequiredClaimsImplicit;
                    case OpenIdConnectFlow.Hybrid:
                        return IdTokenRequiredClaimsHybrid;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(Flow));
                }
            }
        }



        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string GivenName
        {
            get { return GetStringClaim(ClaimNames.GivenName); }
            set { AddClaim(ClaimNames.GivenName, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string FamilyName
        {
            get { return GetStringClaim(ClaimNames.FamilyName); }
            set { AddClaim(ClaimNames.FamilyName, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string MiddleName
        {
            get { return GetStringClaim(ClaimNames.MiddleName); }
            set { AddClaim(ClaimNames.MiddleName, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nickname
        {
            get { return GetStringClaim(ClaimNames.Nickname); }
            set { AddClaim(ClaimNames.Nickname, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string PreferredUsername
        {
            get { return GetStringClaim(ClaimNames.PreferredUsername); }
            set { AddClaim(ClaimNames.PreferredUsername, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Profile
        {
            get { return GetStringClaim(ClaimNames.Profile); }
            set { AddClaim(ClaimNames.Profile, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Picture
        {
            get { return GetStringClaim(ClaimNames.Picture); }
            set { AddClaim(ClaimNames.Picture, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Email
        {
            get { return GetStringClaim(ClaimNames.Email); }
            set { AddClaim(ClaimNames.Email, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public bool? EmailVerified
        {
            get { return GetBoolClaim(ClaimNames.EmailVerified); }
            set { AddClaim(ClaimNames.EmailVerified, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Gender
        {
            get { return GetStringClaim(ClaimNames.Gender); }
            set { AddClaim(ClaimNames.Gender, value); }
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Birthdate
        {
            get { return GetStringClaim(ClaimNames.Birthdate); }
            set { AddClaim(ClaimNames.Birthdate, value); }
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Zoneinfo
        {
            get { return GetStringClaim(ClaimNames.Zoneinfo); }
            set { AddClaim(ClaimNames.Zoneinfo, value); }
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Locale
        {
            get { return GetStringClaim(ClaimNames.Locale); }
            set { AddClaim(ClaimNames.Locale, value); }
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string PhoneNumber
        {
            get { return GetStringClaim(ClaimNames.PhoneNumber); }
            set { AddClaim(ClaimNames.PhoneNumber, value); }
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public bool? PhoneNumberVerified
        {
            get { return GetBoolClaim(ClaimNames.PhoneNumberVerified); }
            set { AddClaim(ClaimNames.PhoneNumberVerified, value); }
        }


        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public Address Address
        {
            get
            {
                var address = GetStringClaim(HeaderParameterNames.Address);
                return string.IsNullOrEmpty(address) ? null : Address.FromJson(address);
            }

            set => Payload[HeaderParameterNames.Address] = value?.ToString();
        }
        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string UpdatedAt
        {
            get { return GetStringClaim(ClaimNames.UpdatedAt); }
            set { AddClaim(ClaimNames.UpdatedAt, value); }
        }
    }
}
