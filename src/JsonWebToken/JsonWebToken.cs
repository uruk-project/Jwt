using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    /// <summary>
    /// A JSON Web Token (JWT).
    /// </summary>
    public class JsonWebToken
    {
        private static string[] EmptyStrings = new string[0];
        private static JProperty[] EmptyClaims = new JProperty[0];
        private readonly JwtPayload _payload;

        protected JsonWebToken()
        {
        }

        public JsonWebToken(JObject header, JsonWebToken nestedToken, IReadOnlyList<int> separators)
        {
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            Header = new JwtHeader(header);
            NestedToken = nestedToken ?? throw new ArgumentNullException(nameof(nestedToken));
            Separators = separators ?? throw new ArgumentNullException(nameof(separators));
        }

        public JsonWebToken(JObject header, string plaintext, IReadOnlyList<int> separators)
        {
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            Header = new JwtHeader(header);
            PlainText = plaintext ?? throw new ArgumentNullException(nameof(plaintext));
            Separators = separators ?? throw new ArgumentNullException(nameof(separators));
        }

        public JsonWebToken(JObject header, JObject payload, IReadOnlyList<int> separators)
        {
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }

            Header = new JwtHeader(header);
            _payload = new JwtPayload(payload);
            Separators = separators ?? throw new ArgumentNullException(nameof(separators));
        }

        /// <summary>
        /// Gets the list of 'audience' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences => Payload?.Aud ?? EmptyStrings;

        /// <summary>
        /// Gets the <see cref="Claim"/>(s) for this token.
        /// If this is a JWE token, this property only returns the encrypted claims;
        ///  the unencrypted claims should be read from the header separately.
        /// </summary>
        public IEnumerable<JProperty> Claims => Payload?.Properties ?? EmptyClaims;

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance if the token is signed.
        /// </summary>
        public virtual JwtHeader Header { get; private set; }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'jti' claim is not found, null is returned.</remarks>
        public string Id => Payload?.Jti ?? string.Empty;

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        public string Issuer => Payload?.Iss ?? string.Empty;

        /// <summary>
        /// Gets the <see cref="JwtPayload"/> associated with this instance.
        /// Note that if this JWT is nested ( <see cref="NestedToken"/> != null, this property represents the payload of the most inner token.
        /// This property can be null if the content type of the most inner token is unrecognized, in that case
        ///  the content of the token is the string returned by PlainText property.
        /// </summary>
        public virtual JwtPayload Payload => NestedToken?.Payload ?? _payload;

        /// <summary>
        /// Gets the <see cref="JsonWebToken"/> associated with this instance.
        /// </summary>
        public JsonWebToken NestedToken { get; set; }

        /// <summary>
        /// Gets the signature algorithm associated with this instance.
        /// </summary>
        /// <remarks>If there is a <see cref="SigningKey"/> associated with this instance, a value will be returned.  Null otherwise.</remarks>
        public string SignatureAlgorithm => Header.Alg;

        /// <summary>
        /// Gets the <see cref="SigningKey"/> to use when writing this token.
        /// </summary>
        public JsonWebKey SigningKey => Header.SigningKey;

        /// <summary>
        /// Gets the <see cref="JsonWebKey"/> to use when writing this token.
        /// </summary>
        public JsonWebKey EncryptionKey => Header.EncryptionKey;

        /// <summary>
        /// Gets the "value" of the 'subject' claim { sub, 'value' }.
        /// </summary>
        public string Subject => Payload?.Sub;

        /// <summary>
        /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? NotBefore => Payload?.NotBefore;

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? ExpirationTime => Payload?.ExpirationTime;

        /// <summary>
        /// Gets the 'value' of the 'isuued at' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? IssuedAt => Payload?.Iat;

        /// <summary>
        /// Gets the plain text of the JWE.
        /// </summary>
        public string PlainText { get; set; }

        public IReadOnlyList<int> Separators { get; }

        public override string ToString()
        {
            if (Payload != null)
            {
                return Header.ToString() + "." + Payload.ToString();
            }
            else
            {
                return Header.ToString() + ".";
            }
        }
    }
}
