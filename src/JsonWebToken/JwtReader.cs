//// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
//// Licensed under the MIT license. See LICENSE in the project root for license information.

//using System;
//using System.Buffers;
//using System.Collections.Generic;
//using System.Linq;
//using System.Runtime.CompilerServices;

//namespace JsonWebToken
//{
//    /// <summary>
//    /// Reads and validates a JWT.
//    /// </summary>
//    public sealed class JwtReader
//    {
//        /// <summary>
//        /// Initializes a new instance of <see cref="JwtReader"/>.
//        /// </summary>
//        /// <param name="encryptionKeyProviders"></param>
//        [Obsolete("This constructor is obsolete. Use method TokenValidationPolicyBuilder.WithEncryptionKeys() instead.")]
//        public JwtReader(ICollection<IKeyProvider> encryptionKeyProviders)
//        {
//        }

//        /// <summary>
//        /// Initializes a new instance of <see cref="JwtReader"/>.
//        /// </summary>
//        /// <param name="encryptionKeys"></param>
//        [Obsolete("This constructor is obsolete. Use method TokenValidationPolicyBuilder.WithEncryptionKeys() instead.")]
//        public JwtReader(params Jwk[] encryptionKeys)
//        {
//        }

//        /// <summary>
//        /// Initializes a new instance of <see cref="JwtReader"/>.
//        /// </summary>
//        /// <param name="encryptionKeyProvider"></param>
//        [Obsolete("This constructor is obsolete. Use method TokenValidationPolicyBuilder.WithEncryptionKeys() instead.")]
//        public JwtReader(IKeyProvider encryptionKeyProvider)
//        {
//        }

//        /// <summary>
//        /// Initializes a new instance of <see cref="JwtReader"/>.
//        /// </summary>
//        /// <param name="encryptionKeys"></param>
//        [Obsolete("This constructor is obsolete. Use method TokenValidationPolicyBuilder.WithEncryptionKeys() instead.")]
//        public JwtReader(Jwks encryptionKeys)
//        {
//        }

//        /// <summary>
//        /// Initializes a new instance of <see cref="JwtReader"/>.
//        /// </summary>
//        /// <param name="encryptionKey"></param>
//        [Obsolete("This constructor is obsolete. Use method TokenValidationPolicyBuilder.WithEncryptionKeys() instead.")]
//        public JwtReader(Jwk encryptionKey)
//        {
//        }

//        /// <summary>
//        /// Initializes a new instance of <see cref="JwtReader"/>.
//        /// </summary>
//        public JwtReader()
//        {
//        }

//        /// <summary>
//        /// Defines whether the header will be cached. Default is <c>true</c>.
//        /// </summary>
//        [Obsolete("This property is obsolete. Use TokenValidationPolicyBuilder.DisabledHeaderCache() instead.")]
//        public bool EnableHeaderCaching { get; set; } = true;

//        /// <summary>
//        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
//        /// </summary>
//        /// <param name="token">The JWT encoded as JWE or JWS</param>
//        /// <param name="policy">The validation policy.</param>
//        [Obsolete("Use the method TryReadToken(string token, TokenValidationPolicy policy, out Jwt jwt) instead.")]
//        public TokenValidationResult TryReadToken(string token, TokenValidationPolicy policy)
//        {
//            if (TryReadToken(token, policy, out Jwt jwt))
//            {
//                return TokenValidationResult.Success(jwt);
//            }
//            else
//            {
//                return new TokenValidationResult(jwt);
//            }
//        }

//        /// <summary>
//        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
//        /// </summary>
//        /// <param name="token">The JWT encoded as JWE or JWS</param>
//        /// <param name="policy">The validation policy.</param>
//        /// <param name="jwt">The resulting JWT.</param>
//        /// <returns><c>True</c> when the token has been successfuly read. <c>False</c> otherwise.</returns>
//        public bool TryReadToken(string token, TokenValidationPolicy policy, out Jwt jwt)
//        {
//            if (token is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.token);
//            }

//            if (policy is null)
//            {
//                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.policy);
//            }

//            if (token.Length == 0)
//            {
//                jwt = new Jwt(TokenValidationError.MalformedToken());
//                return false;
//            }

//            int length = Utf8.GetMaxByteCount(token.Length);
//            if (length > policy.MaximumTokenSizeInBytes)
//            {
//                jwt = new Jwt(TokenValidationError.MalformedToken());
//                return false;
//            }

//            byte[]? utf8ArrayToReturnToPool = null;
//            var utf8Token = length <= Constants.MaxStackallocBytes
//                  ? stackalloc byte[length]
//                  : (utf8ArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(length));
//            try
//            {
//                int bytesWritten = Utf8.GetBytes(token, utf8Token);
//                return Jwt.TryParse(utf8Token.Slice(0, bytesWritten), policy, out jwt);
//            }
//            finally
//            {
//                if (utf8ArrayToReturnToPool != null)
//                {
//                    ArrayPool<byte>.Shared.Return(utf8ArrayToReturnToPool);
//                }
//            }
//        }

//        /// <summary>
//        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
//        /// </summary>
//        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
//        /// <param name="policy">The validation policy.</param>
//        [Obsolete("Use the method TryReadToken(ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy, out Jwt jwt) instead.")]
//        public TokenValidationResult TryReadToken(in ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy)
//        {
//            if (TryReadToken(utf8Token, policy, out Jwt jwt))
//            {
//                return TokenValidationResult.Success(jwt);
//            }
//            else
//            {
//                return new TokenValidationResult(jwt);
//            }
//        }

//        /// <summary>
//        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
//        /// </summary>
//        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
//        /// <param name="policy">The validation policy.</param>
//        /// <param name="jwt">The resulting JWT.</param>
//        /// <returns><c>True</c> when the token has been successfuly read. <c>False</c> otherwise.</returns>
//        public bool TryReadToken(in ReadOnlySequence<byte> utf8Token, TokenValidationPolicy policy, out Jwt jwt)
//        {
//            if (utf8Token.IsSingleSegment)
//            {
//                return Jwt.TryParse(utf8Token.First.Span, policy, out jwt);
//            }

//            return Jwt.TryParse(utf8Token.ToArray(), policy, out jwt);
//        }

//        /// <summary>
//        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
//        /// </summary>
//        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
//        /// <param name="policy">The validation policy.</param>
//        /// <param name="jwt">The resulting JWT.</param>
//        /// <returns><c>True</c> when the token has been successfuly read. <c>False</c> otherwise.</returns>
//        public bool TryReadToken(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy, out Jwt jwt)
//        {
//            return Jwt.TryParse(utf8Token, policy, out jwt);
//        }

//        /// <summary>
//        /// Reads and validates a JWT encoded as a JWS or JWE in compact serialized format.
//        /// </summary>
//        /// <param name="utf8Token">The JWT encoded as JWE or JWS.</param>
//        /// <param name="policy">The validation policy.</param>
//        [Obsolete("Use the method TryReadToken(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy, out Jwt jwt) instead.")]
//        [MethodImpl(MethodImplOptions.NoInlining)]
//        public TokenValidationResult TryReadToken(ReadOnlySpan<byte> utf8Token, TokenValidationPolicy policy)
//        {
//            if (TryReadToken(utf8Token, policy, out Jwt jwt))
//            {
//                return TokenValidationResult.Success(jwt);
//            }
//            else
//            {
//                return new TokenValidationResult(jwt);
//            }
//        }
//    }
//}