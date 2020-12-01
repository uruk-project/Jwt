// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Buffers;

namespace JsonWebToken
{
    /// <summary>Reads and validates a JWT.</summary>
    [Obsolete("This class is obsolete. Use the class " + nameof(Jwt) + " instead.", true)]
    public sealed class JwtReader
    {
        /// <summary>Initializes a new instance of <see cref="JwtReader"/>.</summary>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead, and set an encryption key with the method " + nameof(TokenValidationPolicyBuilder.WithDecryptionKeys) + ".", true)]
        public JwtReader(ICollection<IKeyProvider> encryptionKeyProviders)
            => throw new NotImplementedException();

        /// <summary>Initializes a new instance of <see cref="JwtReader"/>.</summary>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead, and set an encryption key with the method " + nameof(TokenValidationPolicyBuilder.WithDecryptionKeys) + ".", true)]
        public JwtReader(params Jwk[] encryptionKeys)
            => throw new NotImplementedException();

        /// <summary>Initializes a new instance of <see cref="JwtReader"/>.</summary>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead, and set an encryption key with the method " + nameof(TokenValidationPolicyBuilder.WithDecryptionKeys) + ".", true)]
        public JwtReader(IKeyProvider encryptionKeyProvider)
            => throw new NotImplementedException();

        /// <summary>Initializes a new instance of <see cref="JwtReader"/>.</summary>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead, and set an encryption key with the method " + nameof(TokenValidationPolicyBuilder.WithDecryptionKeys) + ".", true)]
        public JwtReader(Jwks encryptionKeys)
            => throw new NotImplementedException();

        /// <summary>Initializes a new instance of <see cref="JwtReader"/>.</summary>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead, and set an encryption key with the method " + nameof(TokenValidationPolicyBuilder.WithDecryptionKey) + ".", true)]
        public JwtReader(Jwk encryptionKey)
            => throw new NotImplementedException();

        /// <summary>Initializes a new instance of <see cref="JwtReader"/>.</summary>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead.", true)]
        public JwtReader()
            => throw new NotImplementedException();

        /// <summary>Defines whether the header will be cached. Default is <c>true</c>.</summary>
        public bool EnableHeaderCaching { get; set; } = true;

        /// <summary>Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.</summary>
        /// <param name="token">The JWT encoded as JWE or JWS</param>
        /// <param name="policy">The validation policy.</param>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead, and set an encryption key with the method " + nameof(TokenValidationPolicyBuilder.WithDecryptionKeys) + " if needed.", true)]
        public TokenValidationResult TryReadToken(string token, TokenValidationPolicy policy)
            => throw new NotImplementedException();

        /// <summary>Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.</summary>
        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
        /// <param name="policy">The validation policy.</param>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead, and set an encryption key with the method " + nameof(TokenValidationPolicyBuilder.WithDecryptionKeys) + " if needed.", true)]
        public TokenValidationResult TryReadToken(in ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy)
            => throw new NotImplementedException();

        /// <summary>Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.</summary>
        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
        /// <param name="policy">The validation policy.</param>
        [Obsolete("This class is obsolete. Use the method " + nameof(Jwt.TryParse) + " instead, and set an encryption key with the method " + nameof(TokenValidationPolicyBuilder.WithDecryptionKeys) + " if needed.", true)]
        public TokenValidationResult TryReadToken(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy)
            => throw new NotImplementedException();
    }
}
