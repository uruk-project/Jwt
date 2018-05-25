using System;

namespace JsonWebToken.Validations
{
    public class TokenReplayValidation : IValidation
    {
        private readonly ITokenReplayCache _tokenReplayCache;

        public TokenReplayValidation(ITokenReplayCache tokenReplayCache)
        {
            _tokenReplayCache = tokenReplayCache ?? throw new ArgumentNullException(nameof(tokenReplayCache));
        }

        public string Name => nameof(TokenReplayValidation);

        public TokenValidationResult TryValidate(ReadOnlySpan<char> token, JsonWebToken jwt)
        {
            if (jwt == null)
            {
                throw new ArgumentNullException(nameof(jwt));
            }

            // check if token if replay cache is set, then there must be an expiration time.
            var expires = jwt.Expires;
            if (!expires.HasValue)
            {
                return TokenValidationResult.NoExpiration(jwt);
            }

            if (!_tokenReplayCache.TryAdd(jwt, expires.Value))
            {
                return TokenValidationResult.TokenReplayed(jwt);
            }

            return TokenValidationResult.Success(jwt);
        }
    }
}
