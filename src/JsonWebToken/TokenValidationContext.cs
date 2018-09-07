using System;

namespace JsonWebToken
{
    public readonly ref struct TokenValidationContext
    {
        public TokenValidationContext(ReadOnlySpan<byte> token, JsonWebToken jwt, SignatureFactory signatureFactory)
        {
            Token = token;
            Jwt = jwt;
            SignatureFactory = signatureFactory;
        }

        public readonly ReadOnlySpan<byte> Token;

        public readonly JsonWebToken Jwt;

        public readonly SignatureFactory SignatureFactory;
    }
}
