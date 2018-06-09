using System;

namespace JsonWebToken
{
    public readonly ref struct TokenValidationContext
    {
        public TokenValidationContext(ReadOnlySpan<byte> token, JsonWebToken jwt)
        {
            Token = token;
            Jwt = jwt;
        }

        public ReadOnlySpan<byte> Token { get; }

        public JsonWebToken Jwt { get; }
    }
}
