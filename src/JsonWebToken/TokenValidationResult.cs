using System;

namespace JsonWebToken
{
    public class TokenValidationResult
    {
        public bool Succedeed => Status == TokenValidationStatus.Success;

        public JsonWebToken Token { get; private set; }

        public TokenValidationStatus Status { get; private set; }

        public string ErrorClaim { get; private set; }
        public string ErrorHeader { get; private set; }
        public Exception Exception { get; private set; }

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

        public static TokenValidationResult MissingSignature(JsonWebToken token)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingSignature,
                Token = token
            };
        }

        public static TokenValidationResult MalformedSignature(JsonWebToken token = null)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MalformedSignature
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
        
        public static TokenValidationResult MissingEncryptionAlgorithm()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingEncryptionAlgorithm
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

        public static TokenValidationResult DecryptionFailed()
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.DecryptionFailed
            };
        }

        public static TokenValidationResult InvalidClaim(JsonWebToken jwt, string claim)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidClaim,
                ErrorClaim = claim
            };
        }

        public static TokenValidationResult MissingClaim(JsonWebToken jwt, string claim)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.MissingClaim,
                ErrorClaim = claim
            };
        }

        public static TokenValidationResult InvalidHeader(JsonWebToken jwt, string header)
        {
            return new TokenValidationResult
            {
                Status = TokenValidationStatus.InvalidHeader,
                ErrorHeader = header
            };
        }

        public static TokenValidationResult MissingHeader(JsonWebToken jwt, string header)
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