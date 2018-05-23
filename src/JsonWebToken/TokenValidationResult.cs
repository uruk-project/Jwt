using System;

namespace JsonWebToken
{
    public class TokenValidationResult
    {
        public bool Succedeed => Status == TokenValidationStatus.Success;

        public JsonWebToken Token { get; private set; }

        public TokenValidationStatus Status { get; private set; }

        public static TokenValidationResult InvalidLifetime(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidLifetime,
                Token = token
            };
        }

        public static TokenValidationResult Expired(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.Expired,
                Token = token
            };
        }

        public static TokenValidationResult TokenReplayed(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.TokenReplayed,
                Token = token
            };
        }

        public static TokenValidationResult MissingIssuer(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingIssuer,
                Token = token
            };
        }

        public static TokenValidationResult InvalidIssuer(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidIssuer,
                Token = token
            };
        }

        public static TokenValidationResult MissingAudience(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingAudience,
                Token = token
            };
        }

        public static TokenValidationResult InvalidAudience(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidAudience,
                Token = token
            };
        }

        public static TokenValidationResult MissingSignature(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingSignature,
                Token = token
            };
        }

        public static TokenValidationResult MalformedSignature(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MalformedSignature,
                Token = token
            };
        }

        public static TokenValidationResult KeyNotFound(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.SignatureKeyNotFound,
                Token = token
            };
        }

        public static TokenValidationResult InvalidSignature(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidSignature,
                Token = token
            };
        }

        public static TokenValidationResult MalformedToken()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MalformedToken,
            };
        }

        public static TokenValidationResult NoExpiration(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingExpirationTime,
                Token = token
            };
        }

        public static TokenValidationResult MissingEncryptionAlgorithm(JsonWebToken jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingEncryptionAlgorithm,
                Token = jwtToken
            };
        }

        public static TokenValidationResult MissingContentType(JsonWebToken jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingContentType,
                Token = jwtToken
            };
        }

        public static TokenValidationResult NotYetValid(JsonWebToken jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.NotYetValid,
                Token = jwtToken
            };
        }

        public static TokenValidationResult Success(JsonWebToken jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.Success,
                Token = jwtToken
            };
        }

        internal static TokenValidationResult DecryptionFailed(JsonWebToken jwtToken)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.DecryptionFailed,
                Token = jwtToken
            };
        }
    }
}