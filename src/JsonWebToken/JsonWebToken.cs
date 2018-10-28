// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

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

        public JsonWebToken(JwtHeader header, JwtPayload payload)
        {
            Header = header ?? throw new ArgumentNullException(nameof(header));
            _payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }
        
        /// <summary>
        /// Gets the list of 'aud' claim.
        /// </summary>
        public IEnumerable<string> Audiences => Payload?.Aud ?? EmptyStrings;

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance if the token is signed.
        /// </summary>
        public virtual JwtHeader Header { get; private set; }

        /// <summary>
        /// Gets the value of the 'jti' claim.
        /// </summary>
        public string Id => Payload?.Jti;

        /// <summary>
        /// Gets the value of the 'iss' claim.
        /// </summary>
        public string Issuer => Payload?.Iss;

        /// <summary>
        /// Gets the <see cref="JwtPayload"/> associated with this instance.
        /// </summary>
        public virtual JwtPayload Payload => NestedToken?.Payload ?? _payload;

        /// <summary>
        /// Gets the nested <see cref="JsonWebToken"/> associated with this instance.
        /// </summary>
        public JsonWebToken NestedToken { get; set; }

        /// <summary>
        /// Gets the signature algorithm associated with this instance.
        /// </summary>
        public SignatureAlgorithm SignatureAlgorithm => Header.Alg;

        /// <summary>
        /// Gets the <see cref="JsonWebKey"/> used for the signature of this token.
        /// </summary>
        public JsonWebKey SigningKey { get; set; }

        /// <summary>
        /// Gets the <see cref="JsonWebKey"/> used for the encryption of this token.
        /// </summary>
        public JsonWebKey EncryptionKey { get; set; }

        /// <summary>
        /// Gets the value of the 'sub'.
        /// </summary>
        public string Subject => Payload?.Sub;

        /// <summary>
        /// Gets the'value of the 'nbf'.
        /// </summary>
        public DateTime? NotBefore => Payload?.Nbf;

        /// <summary>
        /// Gets the value of the 'exp' claim.
        /// </summary>
        public DateTime? ExpirationTime => Payload?.Exp;

        /// <summary>
        /// Gets the value of the 'iat' claim.
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? IssuedAt => Payload?.Iat;

        /// <summary>
        /// Gets the plaintext of the JWE.
        /// </summary>
        public string Plaintext => Encoding.UTF8.GetString(Binary);

        /// <summary>
        /// Gets the binary data of the JWE.
        /// </summary>
        public byte[] Binary { get; set; }

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
