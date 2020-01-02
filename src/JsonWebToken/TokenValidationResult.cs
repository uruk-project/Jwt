// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the result of a token validation.
    /// </summary>
    public sealed class TokenValidationResult
    {
        /// <summary>
        /// Gets whether the token validation is successful.
        /// </summary>
        public bool Succedeed => Status == TokenValidationStatus.Success;

        /// <summary>
        /// Gets of set the <see cref="Jwt"/>.
        /// </summary>
        public Jwt? Token { get; private set; }

        /// <summary>
        /// Gets the status of the validation.
        /// </summary>
        public TokenValidationStatus Status { get; private set; }

        /// <summary>
        /// Gets the claim that caused the error.
        /// </summary>
        public string? ErrorClaim { get; private set; }

        /// <summary>
        /// Gets the header parameter that cause the error.
        /// </summary>
        public string? ErrorHeader { get; private set; }

        /// <summary>
        /// Gets the <see cref="Exception"/> that caused the error.
        /// </summary>
        public Exception? Exception { get; private set; }

        /// <summary>
        /// The token has expired, according to the 'nbf' claim.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult Expired(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.Expired,
                Token = token
            };
        }

        /// <summary>
        /// The token was already validated previously.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult TokenReplayed(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.TokenReplayed,
                Token = token
            };
        }

        /// <summary>
        /// The 'crit' header defines an unsupported header.
        /// </summary>
        /// <param name="criticalHeader"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult CriticalHeaderUnsupported(string criticalHeader)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.CriticalHeaderUnsupported,
                ErrorHeader = criticalHeader
            };
        }

        /// <summary>
        /// The signature is not present.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingSignature(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingSignature,
                Token = token
            };
        }

        /// <summary>
        /// The signature is not base64url encoded.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="e"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MalformedSignature(Jwt token, Exception? e = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MalformedSignature,
                Token = token,
                Exception = e
            };
        }

        /// <summary>
        /// The signature key is not found.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult SignatureKeyNotFound(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.SignatureKeyNotFound,
                Token = token
            };
        }

        /// <summary>
        /// The signature is invalid.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidSignature(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidSignature,
                Token = token
            };
        }

        /// <summary>
        /// The encryption key was not found.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult EncryptionKeyNotFound()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.EncryptionKeyNotFound
            };
        }

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        /// <param name="exception"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MalformedToken(Exception? exception = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MalformedToken,
                Exception = exception
            };
        }

        /// <summary>
        /// The 'enc' header parameter is missing.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingEncryptionAlgorithm()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingEncryptionAlgorithm
            };
        }

        /// <summary>
        /// The token is not yet valid, according to the 'nbf' claim.
        /// </summary>
        /// <param name="jwtToken"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult NotYetValid(Jwt jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.NotYetValid,
                Token = jwtToken
            };
        }

        /// <summary>
        /// The token is valid.
        /// </summary>
        /// <param name="jwtToken"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult Success(Jwt? jwtToken = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.Success,
                Token = jwtToken
            };
        }

        /// <summary>
        /// The token decryption has failed.
        /// </summary>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult DecryptionFailed()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.DecryptionFailed
            };
        }

        /// <summary>
        /// The token has an invalid claim.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidClaim(Jwt jwt, ReadOnlySpan<byte> claim)
        {
            return new TokenValidationResult
            {
                Token = jwt,
                Status = TokenValidationStatus.InvalidClaim,
                ErrorClaim = Encoding.UTF8.GetString(claim.ToArray())
            };
        }

        /// <summary>
        /// The token has an invalid claim.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidClaim(Jwt jwt, string claim)
        {
            return new TokenValidationResult
            {
                Token = jwt,
                Status = TokenValidationStatus.InvalidClaim,
                ErrorClaim = claim
            };
        }

        /// <summary>
        /// The token has a missing claim.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingClaim(Jwt jwt, ReadOnlySpan<byte> claim)
        {
            return new TokenValidationResult
            {
                Token = jwt,
                Status = TokenValidationStatus.MissingClaim,
                ErrorClaim = Encoding.UTF8.GetString(claim.ToArray())
            };
        }

        /// <summary>
        /// The token has a missing claim.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingClaim(Jwt jwt, string claim)
        {
            return new TokenValidationResult
            {
                Token = jwt,
                Status = TokenValidationStatus.MissingClaim,
                ErrorClaim = claim
            };
        }

        /// <summary>
        /// The token has an invalid header. 
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidHeader(ReadOnlySpan<byte> header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidHeader,
                ErrorHeader = Encoding.UTF8.GetString(header.ToArray())
            };
        }

        /// <summary>
        /// The token has an invalid header. 
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult InvalidHeader(string header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidHeader,
                ErrorHeader = header
            };
        }

        /// <summary>
        /// The token has a missing header.
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult MissingHeader(ReadOnlySpan<byte> header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingHeader,
                ErrorHeader = Encoding.UTF8.GetString(header.ToArray())
            };
        }

        /// <summary>
        /// The token decompression has failed.
        /// </summary>
        /// <param name="exception"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static TokenValidationResult DecompressionFailed(Exception? exception = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.DecompressionFailed,
                Exception = exception
            };
        }
    }
}