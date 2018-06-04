using System;

namespace JsonWebToken
{
    public readonly ref struct TokenValidationContext
    {
        public TokenValidationContext(ReadOnlySpan<char> token, JsonWebToken jwt)
        {
            Token = token;
            Jwt = jwt;
        }

        public ReadOnlySpan<char> Token { get; }

        public JsonWebToken Jwt { get; }
    }
}
