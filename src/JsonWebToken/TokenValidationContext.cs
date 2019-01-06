// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken
{
    /// <summary>
    /// Represents the context for validating a token.
    /// </summary>
    public readonly ref struct TokenValidationContext
    {
        /// <summary>
        /// Initializes a new instance of <see cref="TokenValidationContext"/>.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="signatureFactory"></param>
        /// <param name="contentSegment"></param>
        /// <param name="signatureSegment"></param>
        public TokenValidationContext(
            Jwt jwt, 
            SignerFactory signatureFactory,
            ReadOnlySpan<byte> contentSegment,
            ReadOnlySpan<byte> signatureSegment)
        {
            Jwt = jwt;
            SignatureFactory = signatureFactory;
            ContentSegment = contentSegment;
            SignatureSegment = signatureSegment;
        }

        /// <summary>
        /// The decoded JWT.
        /// </summary>
        public readonly Jwt Jwt;

        /// <summary>
        /// The <see cref="SignerFactory"/>.
        /// </summary>
        public readonly SignerFactory SignatureFactory;

        /// <summary>
        /// The <see cref="TokenSegment"/> containing the header and the payload
        /// </summary>
        public readonly ReadOnlySpan<byte> ContentSegment;

        /// <summary>
        /// The <see cref="TokenSegment"/> containing the signature.
        /// </summary>
        public readonly ReadOnlySpan<byte> SignatureSegment;
    }
}
