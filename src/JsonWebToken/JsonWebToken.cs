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

        public JsonWebToken(JObject header, JsonWebToken nestedToken, IList<int> separators)
        {
            Header = new JwtHeader(header);
            NestedToken = nestedToken;
            Separators = separators;
        }

        public JsonWebToken(JObject header, string plaintext, IList<int> separators)
        {
            Header = new JwtHeader(header);
            PlainText = plaintext;
            Separators = separators;
        }

        public JsonWebToken(JObject header, JObject payload, IList<int> separators)
        {
            Header = new JwtHeader(header);
            _payload = new JwtPayload(payload);
            Separators = separators;
        }

        ///// <summary>
        ///// Gets the original raw data of this instance when it was created.
        ///// </summary>
        //public ReadOnlyMemory<char> RawHeader => RawData.AsSpan().Slice(0, Separators[0]);

        ///// <summary>
        ///// Gets the original raw data of this instance when it was created.
        ///// </summary>
        //public ReadOnlySpan<char> RawPayload => RawData.AsSpan().Slice(Separators[0] + 1, Separators[1] - 1);

        /// <summary>
        /// Gets the list of 'audience' claim { aud, 'value' }.
        /// </summary>
        /// <remarks>If the 'audience' claim is not found, enumeration will be empty.</remarks>
        public IEnumerable<string> Audiences
        {
            get
            {
                if (Payload != null)
                {
                    return Payload.Aud ?? EmptyStrings;
                }

                return EmptyStrings;
            }
        }

        /// <summary>
        /// Gets the <see cref="Claim"/>(s) for this token.
        /// If this is a JWE token, this property only returns the encrypted claims;
        ///  the unencrypted claims should be read from the header separately.
        /// </summary>
        public IEnumerable<JProperty> Claims
        {
            get
            {
                if (Payload != null)
                {
                    return Payload.Properties;
                }

                return EmptyClaims;
            }
        }

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance if the token is signed.
        /// </summary>
        public JwtHeader Header { get; private set; }

        /// <summary>
        /// Gets the 'value' of the 'JWT ID' claim { jti, ''value' }.
        /// </summary>
        /// <remarks>If the 'jti' claim is not found, null is returned.</remarks>
        public string Id
        {
            get
            {
                if (Payload != null)
                {
                    return Payload.Jti;
                }

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'issuer' claim { iss, 'value' }.
        /// </summary>
        public string Issuer
        {
            get
            {
                if (Payload != null)
                {
                    return Payload.Iss;
                }

                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the <see cref="JwtPayload"/> associated with this instance.
        /// Note that if this JWT is nested ( <see cref="NestedToken"/> != null, this property represents the payload of the most inner token.
        /// This property can be null if the content type of the most inner token is unrecognized, in that case
        ///  the content of the token is the string returned by PlainText property.
        /// </summary>
        public JwtPayload Payload
        {
            get
            {
                if (NestedToken != null)
                {
                    return NestedToken.Payload;
                }

                //if (_payload == null)
                //{
                //    _payload = JwtPayload.Base64UrlDeserialize(RawPayload);
                //}

                return _payload;
            }
        }

        /// <summary>
        /// Gets the <see cref="JsonWebToken"/> associated with this instance.
        /// </summary>
        public JsonWebToken NestedToken { get; set; }

        ///// <summary>
        ///// Gets the original raw data of this instance when it was created.
        ///// </summary>
        //public ReadOnlySpan<char> RawEncryptedKey { get => RawData.AsSpan().Slice(Separators[0] + 1, Separators[1] - 1); }

        ///// <summary>
        ///// Gets the original raw data of this instance when it was created.
        ///// </summary>
        //public ReadOnlySpan<char> RawInitializationVector { get => RawData.AsSpan().Slice(Separators[0] + Separators[1] + 1, Separators[2] - 1); }

        ///// <summary>
        ///// Gets the original raw data of this instance when it was created.
        ///// </summary>
        //public ReadOnlySpan<char> RawCiphertext { get => RawData.Slice(Separators[0] + Separators[1] + Separators[2] + 1, Separators[3] - 1); }

        ///// <summary>
        ///// Gets the original raw data of this instance when it was created.
        ///// </summary>
        //public ReadOnlySpan<char> RawAuthenticationTag { get => RawData.AsSpan().Slice(Separators[0] + Separators[1] + Separators[2] + Separators[3] + 1); }

        ///// <summary>
        ///// Gets the original raw data of this instance when it was created.
        ///// </summary>
        //public ReadOnlyMemory<char> RawData { get; private set; }

        ///// <summary>
        ///// Gets the original raw data of this instance when it was created.
        ///// </summary>
        //public ReadOnlySpan<char> RawSignature { get => RawData.AsSpan().Slice(Separators[0] + Separators[1] + 1); }

        //public bool HasSignature => _signature.Length != 0;// RawData.Length > Separators[0] + Separators[1] + 1;

        //public ReadOnlySpan<byte> GetSignatureBytes()
        //{
        //    return _signature;
        //}

        /// <summary>
        /// Gets the signature algorithm associated with this instance.
        /// </summary>
        /// <remarks>If there is a <see cref="SigningKey"/> associated with this instance, a value will be returned.  Null otherwise.</remarks>
        public string SignatureAlgorithm
        {
            get { return Header.Alg; }
        }

        /// <summary>
        /// Gets the <see cref="SigningKey"/> to use when writing this token.
        /// </summary>
        public JsonWebKey SigningKey
        {
            get { return Header.SigningKey; }
        }

        /// <summary>
        /// Gets the <see cref="JsonWebKey"/> to use when writing this token.
        /// </summary>
        public JsonWebKey EncryptionKey
        {
            get { return Header.EncryptionKey; }
        }

        /// <summary>
        /// Gets the "value" of the 'subject' claim { sub, 'value' }.
        /// </summary>
        public string Subject
        {
            get
            {
                if (Payload != null)
                {
                    return Payload.Sub;
                }

                return null;
            }
        }

        /// <summary>
        /// Gets the 'value' of the 'notbefore' claim { nbf, 'value' } converted to a <see cref="DateTime"/> assuming 'value' is seconds since UnixEpoch (UTC 1970-01-01T0:0:0Z).
        /// </summary>
        /// <remarks>If the 'notbefore' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? NotBefore
        {
            get
            {
                if (Payload != null)
                {
                    return Payload.NotBefore;
                }

                return null;
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
                if (Payload != null)
                {
                    return Payload.Expires;
                }

                return null;
            }
        }

        /// <summary>
        /// Gets the plain text of the JWE.
        /// </summary>
        public string PlainText { get; set; }

        public IList<int> Separators { get; }

        public override string ToString()
        {
            if (Payload != null)
            {
                return Header.SerializeToJson() + "." + Payload.ToString();
            }
            else
            {
                return Header.SerializeToJson() + ".";
            }
        }
    }
}
