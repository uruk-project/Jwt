// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using JsonWebToken.Internal;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public class IdTokenDescriptor : JwsDescriptor
    {
        private static readonly IReadOnlyDictionary<string, JTokenType[]> IdTokenRequiredClaims = new Dictionary<string, JTokenType[]>
        {
            { Claims.Iss, new [] { JTokenType.String} },
            { Claims.Sub, new [] { JTokenType.String} },
            { Claims.Aud, new [] { JTokenType.String, JTokenType.Array} },
            { Claims.Exp, new [] { JTokenType.Integer } },
            { Claims.Iat, new [] { JTokenType.Integer } }
        };
        private static readonly IReadOnlyDictionary<string, JTokenType[]> IdTokenRequiredClaimsImplicit = new Dictionary<string, JTokenType[]>
        {
            { Claims.Iss, new [] { JTokenType.String} },
            { Claims.Sub, new [] { JTokenType.String} },
            { Claims.Aud, new [] { JTokenType.String, JTokenType.Array} },
            { Claims.Exp, new [] { JTokenType.Integer } },
            { Claims.Iat, new [] { JTokenType.Integer } },
            { Claims.Nonce, new [] { JTokenType.String} },
            { Claims.AtHash, new [] { JTokenType.String } }
        };
        private static readonly IReadOnlyDictionary<string, JTokenType[]> IdTokenRequiredClaimsHybrid = new Dictionary<string, JTokenType[]>
        {
            { Claims.Iss, new [] { JTokenType.String } },
            { Claims.Sub, new [] { JTokenType.String } },
            { Claims.Aud, new [] { JTokenType.String, JTokenType.Array} },
            { Claims.Exp, new [] { JTokenType.Integer } },
            { Claims.Iat, new [] { JTokenType.Integer } },
            { Claims.Nonce, new [] { JTokenType.String } },
            { Claims.AtHash, new [] { JTokenType.String } },
            { Claims.CHash, new [] { JTokenType.String } }
        };

        public IdTokenDescriptor()
            :base()
        {
        }

        public IdTokenDescriptor(JObject  header, JObject payload)
            : base(header, payload)
        {
        }

        public IdTokenDescriptor(JObject payload)
            : base(new JObject(), payload)
        {
        }

        public OpenIdConnectFlow Flow { get; set; }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public DateTime? AuthenticationTime
        {
            get => GetDateTime(Claims.AuthTime);
            set => AddClaim(Claims.AuthTime, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nonce
        {
            get => GetStringClaim(Claims.Nonce);
            set => AddClaim(Claims.Nonce, value);
        }

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string AuthenticationContextClassReference
        {
            get => GetStringClaim(Claims.Acr);
            set => AddClaim(Claims.Acr, value);
        }

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string> AuthenticationMethodsReferences => GetListClaims(Claims.Amr);

        public void AddAuthenticationMethodsReferences(string acr)
        {
            AddClaim(Claims.Acr, acr);
        }

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string AuthorizedParty
        {
            get => GetStringClaim(Claims.Azp);
            set => AddClaim(Claims.Azp, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AccessTokenHash
        {
            get => GetStringClaim(Claims.AtHash);
            set => AddClaim(Claims.AtHash, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string CodeHash
        {
            get => GetStringClaim(Claims.CHash);
            set => AddClaim(Claims.CHash, value);
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
            get => GetStringClaim(Claims.GivenName);
            set => AddClaim(Claims.GivenName, value);
        }

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string FamilyName
        {
            get => GetStringClaim(Claims.FamilyName);
            set => AddClaim(Claims.FamilyName, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string MiddleName
        {
            get => GetStringClaim(Claims.MiddleName);
            set => AddClaim(Claims.MiddleName, value);
        }

        /// <summary>
        /// Gets or sets the Casual name of the End-User.
        /// </summary>
        public string Nickname
        {
            get => GetStringClaim(Claims.Nickname);
            set => AddClaim(Claims.Nickname, value);
        }

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string PreferredUsername
        {
            get => GetStringClaim(Claims.PreferredUsername);
            set => AddClaim(Claims.PreferredUsername, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string Profile
        {
            get => GetStringClaim(Claims.Profile);
            set => AddClaim(Claims.Profile, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string Picture
        {
            get => GetStringClaim(Claims.Picture);
            set => AddClaim(Claims.Picture, value);
        }

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string Website
        {
            get => GetStringClaim(Claims.Website);
            set => AddClaim(Claims.Website, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string Email
        {
            get => GetStringClaim(Claims.Email);
            set => AddClaim(Claims.Email, value);
        }

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified
        {
            get => GetBoolClaim(Claims.EmailVerified);
            set => AddClaim(Claims.EmailVerified, value);
        }

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string Gender
        {
            get => GetStringClaim(Claims.Gender);
            set => AddClaim(Claims.Gender, value);
        }

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string Birthdate
        {
            get => GetStringClaim(Claims.Birthdate);
            set => AddClaim(Claims.Birthdate, value);
        }

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Zoneinfo
        {
            get => GetStringClaim(Claims.Zoneinfo);
            set => AddClaim(Claims.Zoneinfo, value);
        }

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string Locale
        {
            get => GetStringClaim(Claims.Locale);
            set => AddClaim(Claims.Locale, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string PhoneNumber
        {
            get => GetStringClaim(Claims.PhoneNumber);
            set => AddClaim(Claims.PhoneNumber, value);
        }

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified
        {
            get => GetBoolClaim(Claims.PhoneNumberVerified);
            set => AddClaim(Claims.PhoneNumberVerified, value);
        }

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
        /// </summary>
        public Address Address
        {
            get
            {
                var address = GetStringClaim(HeaderParameters.Address);
                return string.IsNullOrEmpty(address) ? null : Address.FromJson(address);
            }

            set => Payload[HeaderParameters.Address] = value?.ToString();
        }

        /// <summary>
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt
        {
            get => GetDateTime(Claims.UpdatedAt);
            set => AddClaim(Claims.UpdatedAt, value);
        }
    }
}
