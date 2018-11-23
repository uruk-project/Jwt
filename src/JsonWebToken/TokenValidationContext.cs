// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    public readonly ref struct TokenValidationContext
    {
        public TokenValidationContext(
            ReadOnlySpan<byte> token, 
            Jwt jwt, 
            ISignerFactory signatureFactory,
            TokenSegment contentSegment,
            TokenSegment signatureSegment)
        {
            Token = token;
            Jwt = jwt;
            SignatureFactory = signatureFactory;
            ContentSegment = contentSegment;
            SignatureSegment = signatureSegment;
        }

        public readonly ReadOnlySpan<byte> Token;

        public readonly Jwt Jwt;

        public readonly ISignerFactory SignatureFactory;

        public readonly TokenSegment ContentSegment;

        public readonly TokenSegment SignatureSegment;
    }
}
