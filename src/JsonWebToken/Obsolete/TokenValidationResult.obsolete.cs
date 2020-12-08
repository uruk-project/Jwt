// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.ComponentModel;

namespace JsonWebToken
{
    /// <summary>Represents the result of a token validation.</summary>
    [Obsolete("This class is obsolete. Use the class " + nameof(TokenValidationError) + " instead.", true)]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class TokenValidationResult
    {
        /// <summary>Gets whether the token validation is successful.</summary>
        [Obsolete("This property is obsolete. Use the result of the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public bool Succedeed => throw new NotImplementedException();

        /// <summary>Gets of set the <see cref="Jwt"/>.</summary>
        [Obsolete("This property is obsolete. Use the parameter \"token\" of the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public Jwt? Token => throw new NotImplementedException();

        /// <summary>Gets the status of the validation.</summary>
        [Obsolete("This property is obsolete. Use the parameter \"error\" of the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public TokenValidationStatus Status => throw new NotImplementedException();

        /// <summary>Gets the claim that caused the error.</summary>
        [Obsolete("This property is obsolete. Use the parameter \"error\" of the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public string? ErrorClaim => throw new NotImplementedException();

        /// <summary>Gets the header parameter that cause the error.</summary>
        [Obsolete("This property is obsolete. Use the parameter \"error\" of the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public string? ErrorHeader => throw new NotImplementedException();

        /// <summary>Gets the <see cref="Exception"/> that caused the error.</summary>
        [Obsolete("This property is obsolete. Use the parameter \"error\" of the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public Exception? Exception => throw new NotImplementedException();

        /// <summary>The token has expired, according to the 'nbf' claim.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.Expired) + " instead.", true)]
        public static TokenValidationResult Expired(Jwt token)
            => throw new NotImplementedException();

        /// <summary>The token was already validated previously.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.TokenReplayed) + " instead.", true)]
        public static TokenValidationResult TokenReplayed(Jwt token)
            => throw new NotImplementedException();

        /// <summary>The 'crit' header defines an unsupported header.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.CriticalHeaderUnsupported) + " instead.", true)]
        public static TokenValidationResult CriticalHeaderUnsupported(string criticalHeader)
            => throw new NotImplementedException();

        /// <summary>The encryption key was not found.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.EncryptionKeyNotFound) + " instead.", true)]
        public static TokenValidationResult EncryptionKeyNotFound()
            => throw new NotImplementedException();

        /// <summary>The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.MalformedToken) + " instead.", true)]
        public static TokenValidationResult MalformedToken()
            => throw new NotImplementedException();

        /// <summary>The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.MalformedToken) + " instead.", true)]
        public static TokenValidationResult MalformedToken(Exception exception)
            => throw new NotImplementedException();

        /// <summary>The 'enc' header parameter is missing.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.MissingEncryptionAlgorithm) + " instead.", true)]
        public static TokenValidationResult MissingEncryptionAlgorithm()
            => throw new NotImplementedException();

        /// <summary>The token is not yet valid, according to the 'nbf' claim.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.NotYetValid) + " instead.", true)]
        public static TokenValidationResult NotYetValid(Jwt jwtToken)
            => throw new NotImplementedException();

        /// <summary>The token is valid.</summary>
        [Obsolete("This property is obsolete. Please return the value true with the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public static TokenValidationResult Success()
            => throw new NotImplementedException();

        /// <summary>The token is valid.</summary>
        [Obsolete("This property is obsolete. Please return the value true with the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public static TokenValidationResult Success(Jwt jwtToken)
            => throw new NotImplementedException();

        /// <summary>The token decryption has failed.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.DecryptionFailed) + " instead.", true)]
        public static TokenValidationResult DecryptionFailed()
            => throw new NotImplementedException();

        /// <summary>The token has an invalid claim.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.InvalidClaim) + " instead.", true)]
        public static TokenValidationResult InvalidClaim(Jwt jwt, ReadOnlySpan<byte> claim)
            => throw new NotImplementedException();

        /// <summary>The token has an invalid claim.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.InvalidClaim) + " instead.", true)]
        public static TokenValidationResult InvalidClaim(Jwt jwt, string claim)
            => throw new NotImplementedException();

        /// <summary>The token has a missing claim.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.MissingClaim) + " instead.", true)]
        public static TokenValidationResult MissingClaim(Jwt jwt, ReadOnlySpan<byte> claim)
            => throw new NotImplementedException();

        /// <summary>The token has a missing claim.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.MissingClaim) + " instead.", true)]
        public static TokenValidationResult MissingClaim(Jwt jwt, string claim)
            => throw new NotImplementedException();

        /// <summary>The token has an invalid header. </summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.InvalidHeader) + " instead.", true)]
        public static TokenValidationResult InvalidHeader(ReadOnlySpan<byte> header)
            => throw new NotImplementedException();

        /// <summary>The token has an invalid header. </summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.InvalidHeader) + " instead.", true)]
        public static TokenValidationResult InvalidHeader(string header)
            => throw new NotImplementedException();

        /// <summary>The token has a missing header.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.MissingHeader) + " instead.", true)]
        public static TokenValidationResult MissingHeader(ReadOnlySpan<byte> header)
            => throw new NotImplementedException();

        /// <summary>The token decompression has failed.</summary>
        [Obsolete("This property is obsolete. Use the method " + nameof(TokenValidationError.MissingHeader) + " instead.", true)]
        public static TokenValidationResult DecompressionFailed(Exception exception)
            => throw new NotImplementedException();
    }
}
