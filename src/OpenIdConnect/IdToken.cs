using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

namespace JsonWebToken
{
    public class IdToken : JsonWebToken
    {
        private readonly JsonWebToken _token;

        public IdToken(JsonWebToken token)
        {
            _token = token ?? throw new ArgumentNullException(nameof(token));
        }

        public override JwtHeader Header => _token.Header;

        public override JwtPayload Payload => _token.Payload;

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public DateTime? AuthenticationTime => ToDateTime(Payload[Claims.AuthTime]);

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Nonce => Payload[Claims.Nonce]?.Value<string>();

        /// <summary>
        /// Authentication Context Class that the authentication performed satisfied.
        /// </summary>
        public string AuthenticationContextClassReference => Payload[Claims.Acr]?.Value<string>();

        /// <summary>
        /// Gets or sets the Authentication Methods References used in the authentication.
        /// </summary>
        public IReadOnlyList<string> AuthenticationMethodsReferences => Payload[Claims.Amr]?.Values<string>().ToList();

        /// <summary>
        /// Gets or sets the Authorized party - the party to which the ID Token was issued.
        /// </summary>
        public string AuthorizedParty => Payload[Claims.Azp]?.Value<string>();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string AccessTokenHash => Payload[Claims.AtHash]?.Value<string>();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string CodeHash => Payload[Claims.CHash]?.Value<string>();

        /// <summary>
        /// Gets or sets the Given name(s) or first name(s) of the End-User.
        /// </summary>
        public string GivenName => Payload[Claims.GivenName]?.Value<string>();

        /// <summary>
        /// Gets or sets the Surname(s) or last name(s) of the End-User.
        /// </summary>
        public string FamilyName => Payload[Claims.FamilyName]?.Value<string>();

        /// <summary>
        /// Gets or sets the middle name(s) of the End-User.
        /// </summary>
        public string MiddleName => Payload[Claims.MiddleName]?.Value<string>();

        /// <summary>
        /// Gets or sets the casual name of the End-User.
        /// </summary>
        public string Nickname => Payload[Claims.Nickname]?.Value<string>();

        /// <summary>
        /// Gets or sets the Shorthand name by which the End-User wishes to be referred to.
        /// </summary>
        public string PreferredUsername => Payload[Claims.PreferredUsername]?.Value<string>();

        /// <summary>
        /// Gets or sets the URL of the End-User's profile page.
        /// </summary>
        public string Profile => Payload[Claims.Profile]?.Value<string>();

        /// <summary>
        /// Gets or sets the URL of the End-User's profile picture.
        /// </summary>
        public string Picture => Payload[Claims.Picture]?.Value<string>();

        /// <summary>
        /// Gets or sets the URL of the End-User's Web page or blog.
        /// </summary>
        public string Website => Payload[Claims.Website]?.Value<string>();

        /// <summary>
        /// Gets or sets the End-User's preferred e-mail address.
        /// </summary>
        public string Email => Payload[Claims.Email]?.Value<string>();

        /// <summary>
        /// True if the End-User's e-mail address has been verified; otherwise false.
        /// </summary>
        public bool? EmailVerified
        {
            get { return Payload[Claims.EmailVerified]?.Value<bool>(); }
        }

        /// <summary>
        /// Gets or sets the End-User's gender. Values defined by this specification are female and male. 
        /// </summary>
        public string Gender => Payload[Claims.Gender]?.Value<string>();

        /// <summary>
        /// Gets or sets the End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
        /// </summary>
        public string Birthdate => Payload[Claims.Birthdate]?.Value<string>();

        /// <summary>
        /// Gets or sets the time when the End-User authentication occurred.
        /// </summary>
        public string Zoneinfo => Payload[Claims.Zoneinfo]?.Value<string>();

        /// <summary>
        /// Gets or sets the End-User's locale, represented as a BCP47 [RFC5646] language tag.
        /// </summary>
        public string Locale => Payload[Claims.Locale]?.Value<string>();

        /// <summary>
        /// Gets or sets the End-User's preferred telephone number.
        /// </summary>
        public string PhoneNumber => Payload[Claims.PhoneNumber]?.Value<string>();

        /// <summary>
        /// True if the End-User's phone number has been verified; otherwise false.
        /// </summary>
        public bool? PhoneNumberVerified => Payload[Claims.PhoneNumberVerified]?.Value<bool>();

        /// <summary>
        /// Gets or sets the End-User's preferred postal address.
        /// </summary>
        public Address Address
        {
            get
            {
                var address = Payload[Claims.Address]?.Value<string>();
                return address == null ? null : Address.FromJson(address);
            }
        }

        /// <summary>
        /// Gets or sets the time the End-User's information was last updated.
        /// </summary>
        public DateTime? UpdatedAt => ToDateTime(Payload[Claims.UpdatedAt]);

        private static DateTime? ToDateTime(JToken token)
        {
            if (token == null || token.Type == JTokenType.Null)
            {
                return default;
            }

            return EpochTime.ToDateTime(token.Value<long>());
        }
    }
}