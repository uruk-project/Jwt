using JsonWebToken.Internal;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// A JSON Web Token (JWT).
    /// </summary>
    public class JsonWebToken
    {
        private static readonly string[] EmptyStrings = Array.Empty<string>();
        private readonly JwtPayload _payload;

        protected JsonWebToken()
        {
        }

        public JsonWebToken(JwtHeader header, JsonWebToken nestedToken)
        {
            Header = header ?? throw new ArgumentNullException(nameof(header));
            NestedToken = nestedToken ?? throw new ArgumentNullException(nameof(nestedToken));
        }

        public JsonWebToken(JwtHeader header, byte[] binary)
        {
            Header = header ?? throw new ArgumentNullException(nameof(header));
            Binary = binary ?? throw new ArgumentNullException(nameof(binary));
        }

        public JsonWebToken(JwtHeader header, JwtPayload payload, TokenSegment contentSegment, TokenSegment signatureSegment)
        {
            Header = header ?? throw new ArgumentNullException(nameof(header));
            _payload = payload ?? throw new ArgumentNullException(nameof(payload));
            ContentSegment = contentSegment;
            SignatureSegment = signatureSegment;
        }
        
        /// <summary>
        /// Gets the list of 'audience' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences => Payload?.Aud ?? EmptyStrings;

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance if the token is signed.
        /// </summary>
        public virtual JwtHeader Header { get; private set; }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'jti' claim is not found, null is returned.</remarks>
        public string Id => Payload?.Jti;

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        public string Issuer => Payload?.Iss;

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
        public SignatureAlgorithm SignatureAlgorithm => Header.Alg;

        /// <summary>
        /// Gets the <see cref="SigningKey"/> to use when writing this token.
        /// </summary>
        public JsonWebKey SigningKey { get; set; }

        /// <summary>
        /// Gets the <see cref="JsonWebKey"/> to use when writing this token.
        /// </summary>
        public JsonWebKey EncryptionKey { get; set; }

        /// <summary>
        /// Gets the "value" of the 'subject' claim { sub, 'value' }.
        /// </summary>
        public string Subject => Payload?.Sub;

        /// <summary>
        /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? NotBefore => Payload?.Nbf;

        /// <summary>
        /// Gets the 'value' of the 'expiration' claim { exp, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? ExpirationTime => Payload?.Exp;

        /// <summary>
        /// Gets the 'value' of the 'isuued at' claim { iat, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? IssuedAt => Payload?.Iat;

        /// <summary>
        /// Gets the plaintext of the JWE.
        /// </summary>
        public string Plaintext => Encoding.UTF8.GetString(Binary);

        public IReadOnlyList<int> Separators { get; }

        public byte[] Binary { get; set; }

        public TokenSegment ContentSegment { get; }

        public TokenSegment SignatureSegment { get; }

        public override string ToString()
        {
            if (Payload != null)
            {
                return JsonConvert.SerializeObject(Header) + "." + JsonConvert.SerializeObject(Payload);
            }
            else
            {
                return JsonConvert.SerializeObject(Header) + ".";
            }
        }
    }
}
