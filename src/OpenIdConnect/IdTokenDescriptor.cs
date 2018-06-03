using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebTokens
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
            : base(payload)
        {
        }

        public OpenIdConnectFlow Flow { get; set; }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public DateTime? AuthenticationTime
        {
            get => GetDateTime(ClaimNames.AuthTime);
            set => AddClaim(ClaimNames.AuthTime, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nonce
        {
            get => GetStringClaim(ClaimNames.Nonce);
            set => AddClaim(ClaimNames.Nonce, value);
        }

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string AuthenticationContextClassReference
        {
            get => GetStringClaim(ClaimNames.Acr);
            set => AddClaim(ClaimNames.Acr, value);
        }

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string> AuthenticationMethodsReferences => GetListClaims(ClaimNames.Amr);

        public void AddAuthenticationMethodsReferences(string acr)
        {
            AddClaim(ClaimNames.Acr, acr);
        }

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string AuthorizedParty
        {
            get => GetStringClaim(ClaimNames.Azp);
            set => AddClaim(ClaimNames.Azp, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AccessTokenHash
        {
            get => GetStringClaim(ClaimNames.AtHash);
            set => AddClaim(ClaimNames.AtHash, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string CodeHash
        {
            get => GetStringClaim(ClaimNames.CHash);
            set => AddClaim(ClaimNames.CHash, value);
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
        /// Gets or sets the Given name(s) or first name(s) of the End-User.
        /// </summary>
        public string GivenName
        {
            get => GetStringClaim(ClaimNames.GivenName);
            set => AddClaim(ClaimNames.GivenName, value);
        }

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string FamilyName
        {
            get => GetStringClaim(ClaimNames.FamilyName);
            set => AddClaim(ClaimNames.FamilyName, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string MiddleName
        {
            get => GetStringClaim(ClaimNames.MiddleName);
            set => AddClaim(ClaimNames.MiddleName, value);
        }

        /// <summary>
        /// Gets or sets the Casual name of the End-User.
        /// </summary>
        public string Nickname
        {
            get => GetStringClaim(ClaimNames.Nickname);
            set => AddClaim(ClaimNames.Nickname, value);
        }

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string PreferredUsername
        {
            get => GetStringClaim(ClaimNames.PreferredUsername);
            set => AddClaim(ClaimNames.PreferredUsername, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string Profile
        {
            get => GetStringClaim(ClaimNames.Profile);
            set => AddClaim(ClaimNames.Profile, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string Picture
        {
            get => GetStringClaim(ClaimNames.Picture);
            set => AddClaim(ClaimNames.Picture, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string Website
        {
            get => GetStringClaim(ClaimNames.Website);
            set => AddClaim(ClaimNames.Website, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string Email
        {
            get => GetStringClaim(ClaimNames.Email);
            set => AddClaim(ClaimNames.Email, value);
        }

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified
        {
            get => GetBoolClaim(ClaimNames.EmailVerified);
            set => AddClaim(ClaimNames.EmailVerified, value);
        }

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string Gender
        {
            get => GetStringClaim(ClaimNames.Gender);
            set => AddClaim(ClaimNames.Gender, value);
        }

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string Birthdate
        {
            get => GetStringClaim(ClaimNames.Birthdate);
            set => AddClaim(ClaimNames.Birthdate, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Zoneinfo
        {
            get => GetStringClaim(ClaimNames.Zoneinfo);
            set => AddClaim(ClaimNames.Zoneinfo, value);
        }

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string Locale
        {
            get => GetStringClaim(ClaimNames.Locale);
            set => AddClaim(ClaimNames.Locale, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string PhoneNumber
        {
            get => GetStringClaim(ClaimNames.PhoneNumber);
            set => AddClaim(ClaimNames.PhoneNumber, value);
        }

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified
        {
            get => GetBoolClaim(ClaimNames.PhoneNumberVerified);
            set => AddClaim(ClaimNames.PhoneNumberVerified, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
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
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt
        {
            get => GetDateTime(ClaimNames.UpdatedAt);
            set => AddClaim(ClaimNames.UpdatedAt, value);
        }
    }
}
