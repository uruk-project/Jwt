// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// A JSON Web Token (JWT).
    /// </summary>
    public class Jwt
    {
        private static readonly string[] EmptyStrings = Array.Empty<string>();
        private readonly JwtPayload? _payload;

        /// <summary>
        /// Initializes a new instance of <see cref="Jwt"/>.
        /// </summary>
        protected Jwt(Jwt token)
        {
            if (token is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.token);
            }

            _payload = token._payload;
            Header = token.Header;
            NestedToken = token.NestedToken;
            SigningKey = token.SigningKey;
            EncryptionKey = token.EncryptionKey;
            Binary = token.Binary;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="Jwt"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="nestedToken"></param>
        /// <param name="encryptionKey"></param>
        public Jwt(JwtHeader header, Jwt nestedToken, Jwk encryptionKey)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (nestedToken is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.nestedToken);
            }

            if (encryptionKey is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionKey);
            }

            Header = header;
            NestedToken = nestedToken;
            EncryptionKey = encryptionKey;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="Jwt"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="data"></param>
        /// <param name="encryptionKey"></param>
        public Jwt(JwtHeader header, byte[] data, Jwk encryptionKey)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (data is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.data);
            }

            if (encryptionKey is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionKey);
            }

            Header = header;
            Binary = data;
            EncryptionKey = encryptionKey;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="Jwt"/>.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <param name="signingKey"></param>
        public Jwt(JwtHeader header, JwtPayload payload, Jwk? signingKey)
        {
            if (header is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.header);
            }

            if (payload is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.payload);
            }
     
            Header = header;
            _payload = payload;
            SigningKey = signingKey;
        }

        /// <summary>
        /// Gets the list of 'aud' claim.
        /// </summary>
        public IEnumerable<string> Audiences => Payload?.Aud ?? EmptyStrings;

        /// <summary>
        /// Gets the <see cref="JwtHeader"/> associated with this instance if the token is signed.
        /// </summary>
        public JwtHeader Header { get; }

        /// <summary>
        /// Gets the value of the 'jti' claim.
        /// </summary>
        public string? Id => Payload?.Jti;

        /// <summary>
        /// Gets the value of the 'iss' claim.
        /// </summary>
        public string? Issuer => Payload?.Iss;

        /// <summary>
        /// Gets the <see cref="JwtPayload"/> associated with this instance.
        /// </summary>
        public JwtPayload? Payload => NestedToken?.Payload ?? _payload;

        /// <summary>
        /// Gets the nested <see cref="Jwt"/> associated with this instance.
        /// </summary>
        public Jwt? NestedToken { get; }

        /// <summary>
        /// Gets the signature algorithm associated with this instance.
        /// </summary>
        public SignatureAlgorithm? SignatureAlgorithm => Header.SignatureAlgorithm;

        /// <summary>
        /// Gets the <see cref="Jwk"/> used for the signature of this token.
        /// </summary>
        public Jwk? SigningKey { get; }

        /// <summary>
        /// Gets the <see cref="Jwk"/> used for the encryption of this token.
        /// </summary>
        public Jwk? EncryptionKey { get; }

        /// <summary>
        /// Gets the value of the 'sub'.
        /// </summary>
        public string? Subject => Payload?.Sub;

        /// <summary>
        /// Gets the'value of the 'nbf'.
        /// </summary>
        public DateTime? NotBefore => EpochTime.ToDateTime(Payload?.Nbf);

        /// <summary>
        /// Gets the value of the 'exp' claim.
        /// </summary>
        public DateTime? ExpirationTime => EpochTime.ToDateTime(Payload?.Exp);

        /// <summary>
        /// Gets the value of the 'iat' claim.
        /// </summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? IssuedAt => EpochTime.ToDateTime(Payload?.Iat);

        /// <summary>
        /// Gets the plaintext of the JWE.
        /// </summary>
        public string? Plaintext => Binary is null ? null : Utf8.GetString(Binary);

        /// <summary>
        /// Gets the binary data of the JWE.
        /// </summary>
        public byte[]? Binary { get; }

        /// <inheritsdoc />
        public override string ToString()
        {
            if (Payload == null)
            {
                return Header.ToString() + ".";
            }
            else if (NestedToken == null)
            {
                return Header.ToString() + "." + Payload.ToString();
            }
            else
            {
                return Header.ToString() + "." + NestedToken.Header.ToString() + "." + NestedToken.Payload;
            }
        }
    }
}