using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace JsonWebToken
{
    public sealed partial class Jwt
    {
        /// <summary>Creates a new instance of <see cref="Jwt"/>.</summary>
        [Obsolete("This method is obsolete. Use the method " + nameof(Jwt.TryParse) + "() instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static Jwt Create(JwtHeader header, Jwt nestedToken, Jwk encryptionKey)
            => throw new NotImplementedException();

        /// <summary>Creates a new instance of <see cref="Jwt"/>.</summary>
        [Obsolete("This method is obsolete. Use the method " + nameof(Jwt.TryParse) + "() instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static Jwt Create(JwtHeader header, byte[] data, Jwk encryptionKey)
            => throw new NotImplementedException();

        /// <summary>Creates a new instance of <see cref="Jwt"/>.</summary>
        [Obsolete("This method is obsolete. Use the method " + nameof(Jwt.TryParse) + "() instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static Jwt Create(JwtHeader header, JwtPayload payload, Jwk? signingKey)
            => throw new NotImplementedException();

        /// <summary>Gets the list of 'aud' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.TryGetClaim(JwtClaimNames.Aud, out var value) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IEnumerable<string> Audiences 
            => throw new NotImplementedException(); 

        /// <summary>Gets the value of the 'jti' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.TryGetClaim(JwtClaimNames.Jti, out var value) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? Id => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the value of the 'iss' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Payload.TryGetClaim(JwtClaimNames.Iss, out var value) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? Issuer => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the nested <see cref="Jwt"/> associated with this instance.</summary>
        [Obsolete("This property is obsolete. Use the property " + nameof(Nested) + " instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Jwt? NestedToken => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the signature algorithm associated with this instance.</summary>
        [Obsolete("This property is obsolete. Use the property Header.SignatureAlgorithm instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public SignatureAlgorithm? SignatureAlgorithm => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the <see cref="Jwk"/> used for the signature of this token.</summary>
        [Obsolete("This property is obsolete.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Jwk? SigningKey => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the <see cref="Jwk"/> used for the encryption of this token.</summary>
        [Obsolete("This property is obsolete.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Jwk? EncryptionKey => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the value of the 'sub'.</summary>
        [Obsolete("This property is obsolete. Use the method Jwt.Payload.TryGetClaim(\"sub\", out JwtElement claim) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public string? Subject => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the'value of the 'nbf'.</summary>
        [Obsolete("This property is obsolete. Use the method Jwt.Payload.TryGetClaim(\"nbf\", out JwtElement claim) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public DateTime? NotBefore => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the value of the 'exp' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Jwt.Payload.TryGetClaim(\"exp\", out JwtElement claim) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public DateTime? ExpirationTime => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the value of the 'iat' claim.</summary>
        [Obsolete("This property is obsolete. Use the method Jwt.Payload.TryGetClaim(\"iat\", out JwtElement claim) instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public DateTime? IssuedAt => throw new NotImplementedException();

        /// <summary>This property is obsolete. Gets the binary data of the JWE.</summary>
        [Obsolete("This property is obsolete. Use the property Jwt.Payload.RawValue instead.", true)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public byte[]? Binary => throw new NotImplementedException();
    }
}