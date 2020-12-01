using System;
using System.Collections.Generic;

namespace JsonWebToken
{
    public sealed partial class Jwt
    {
        /// <summary>Creates a new instance of <see cref="Jwt"/>.</summary>
        public static Jwt Create(JwtHeader header, Jwt nestedToken, Jwk encryptionKey)
            => throw new NotImplementedException();

        /// <summary>Creates a new instance of <see cref="Jwt"/>.</summary>
        public static Jwt Create(JwtHeader header, byte[] data, Jwk encryptionKey)
            => throw new NotImplementedException();

        /// <summary>Creates a new instance of <see cref="Jwt"/>.</summary>
        public static Jwt Create(JwtHeader header, JwtPayload payload, Jwk? signingKey)
            => throw new NotImplementedException();

        /// <summary>Gets the list of 'aud' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.TryGetClaim(JwtClaimNames.Aud, out var value) instead.", true)]
        public IEnumerable<string> Audiences 
            => throw new NotImplementedException(); 

        /// <summary>Gets the value of the 'jti' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.TryGetClaim(JwtClaimNames.Jti, out var value) instead.", true)]
        public string? Id => throw new NotImplementedException();

        /// <summary>Gets the value of the 'iss' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.TryGetClaim(JwtClaimNames.Iss, out var value) instead.", true)]
        public string? Issuer => throw new NotImplementedException();

        /// <summary>Gets the nested <see cref="Jwt"/> associated with this instance.</summary>
        [Obsolete("This property is obsolete. Use the property " + nameof(Nested) + " instead.", true)]
        public Jwt? NestedToken => throw new NotImplementedException();

        /// <summary>Gets the signature algorithm associated with this instance.</summary>
        [Obsolete("This property is obsolete. Use the propert Headeroad.TryGetClaim(JwtClaimNames.Iss, out var value) instead.", true)]
        public SignatureAlgorithm? SignatureAlgorithm => throw new NotImplementedException();

        /// <summary>Gets the <see cref="Jwk"/> used for the signature of this token.</summary>
        public Jwk? SigningKey => throw new NotImplementedException();

        /// <summary>Gets the <see cref="Jwk"/> used for the encryption of this token.</summary>
        public Jwk? EncryptionKey => throw new NotImplementedException();

        /// <summary>Gets the value of the 'sub'.</summary>
        public string? Subject => throw new NotImplementedException();

        /// <summary>Gets the'value of the 'nbf'.</summary>
        public DateTime? NotBefore => throw new NotImplementedException();

        /// <summary>Gets the value of the 'exp' claim.</summary>
        public DateTime? ExpirationTime => throw new NotImplementedException();

        /// <summary>Gets the value of the 'iat' claim.</summary>
        /// <remarks>If the 'expiration' claim is not found, then <see cref="DateTime.MinValue"/> is returned.</remarks>
        public DateTime? IssuedAt => throw new NotImplementedException();

        /// <summary>Gets the binary data of the JWE.</summary>
        public byte[]? Binary => throw new NotImplementedException();
    }
}