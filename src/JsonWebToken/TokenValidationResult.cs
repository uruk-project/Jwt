// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the result of a token validation.
    /// </summary>
    public sealed class TokenValidationResult
    {
        public bool Succedeed => Status == TokenValidationStatus.Success;

        public Jwt Token { get; private set; }

        public TokenValidationStatus Status { get; private set; }

        public string ErrorClaim { get; private set; }

        public string ErrorHeader { get; private set; }

        public Exception Exception { get; private set; }

        public static TokenValidationResult Expired(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.Expired,
                Token = token
            };
        }

        public static TokenValidationResult CriticalHeaderMissing(string criticalHeader)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.CriticalHeaderMissing, 
                ErrorHeader = criticalHeader
            };
        }

        public static TokenValidationResult TokenReplayed(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.TokenReplayed,
                Token = token
            };
        }

        public static TokenValidationResult CriticalHeaderUnsupported(string criticalHeader)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.CriticalHeaderUnsupported,
                ErrorHeader = criticalHeader
            };
        }

        public static TokenValidationResult MissingSignature(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingSignature,
                Token = token
            };
        }

        public static TokenValidationResult MalformedSignature(Jwt token, Exception e = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MalformedSignature, 
                Exception = e
            };
        }

        public static TokenValidationResult SignatureKeyNotFound(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.SignatureKeyNotFound,
                Token = token
            };
        }

        public static TokenValidationResult InvalidSignature(Jwt token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidSignature,
                Token = token
            };
        }

        public static TokenValidationResult EncryptionKeyNotFound()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.EncryptionKeyNotFound
            };
        }

        public static TokenValidationResult MalformedToken(Exception e = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MalformedToken,
                Exception = e
            };
        }

        public static TokenValidationResult MissingEncryptionAlgorithm()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingEncryptionAlgorithm
            };
        }

        public static TokenValidationResult NotYetValid(Jwt jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.NotYetValid,
                Token = jwtToken
            };
        }

        public static TokenValidationResult Success(Jwt jwtToken = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.Success,
                Token = jwtToken
            };
        }

        public static TokenValidationResult DecryptionFailed()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.DecryptionFailed
            };
        }

        public static TokenValidationResult InvalidClaim(Jwt jwt, string claim)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidClaim,
                ErrorClaim = claim
            };
        }

        public static TokenValidationResult MissingClaim(Jwt jwt, string claim)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingClaim,
                ErrorClaim = claim
            };
        }

        public static TokenValidationResult InvalidHeader(string header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidHeader,
                ErrorHeader = header
            };
        }

        public static TokenValidationResult MissingHeader(string header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingHeader,
                ErrorHeader = header
            };
        }

        public static TokenValidationResult DecompressionFailed(Exception exception = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.DecompressionFailed,
                Exception = exception
            };
        }
    }
}