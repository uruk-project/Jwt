// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Validates a token signature.
    /// </summary>
    public abstract class SignatureValidationPolicy
    {
        /// <summary>
        /// Allows to support the unsecure 'none' algorithm that require no signature.
        /// </summary>
        public static readonly SignatureValidationPolicy NoSignature = new NoSignatureValidationContext();

        /// <summary>
        /// Allows to ignore the signature, whatever ther is an algorithm defined or not.
        /// </summary>
        public static readonly SignatureValidationPolicy IgnoreSignature = new IgnoreSignatureValidationPolicy();

        internal static readonly SignatureValidationPolicy InvalidSignature = new InvalidSignatureValidationPolicy();

        /// <summary>
        /// Gets whether the signature validation is enabled.
        /// </summary>
        public abstract bool IsEnabled { get; }

        /// <summary>
        /// Try to validate the token signature.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <returns></returns>
        public abstract SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment);

        /// <summary>
        /// Creates a new <see cref="SignatureValidationPolicy"/> instance.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static SignatureValidationPolicy Create(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
        {
            return new DefaultSignatureValidationPolicy(keyProvider, algorithm);
        }

        /// <summary>
        /// Creates a new <see cref="SignatureValidationPolicy"/> instance.
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="policy"></param>
        /// <returns></returns>
        public static SignatureValidationPolicy Create(string issuer, SignatureValidationPolicy policy)
        {
            return new SingleIssuerSignatureValidationPolicy(issuer, policy);
        }

        /// <summary>
        /// Creates a new <see cref="SignatureValidationPolicy"/> instance.
        /// </summary>
        /// <param name="policies"></param>
        /// <param name="defaultPolicy"></param>
        /// <returns></returns>
        public static SignatureValidationPolicy Create(Dictionary<string, SignatureValidationPolicy> policies, SignatureValidationPolicy defaultPolicy)
        {
            return new MultiIssuersSignatureValidationPolicy(policies, defaultPolicy);
        }

        private sealed class MultiIssuersSignatureValidationPolicy : SignatureValidationPolicy
        {
            private readonly Dictionary<string, SignatureValidationPolicy> _policies;
            private readonly SignatureValidationPolicy _defaultPolicy;

            public MultiIssuersSignatureValidationPolicy(Dictionary<string, SignatureValidationPolicy> policies, SignatureValidationPolicy defaultPolicy)
            {
                _policies = policies;
                _defaultPolicy = defaultPolicy;
            }

            public override bool IsEnabled => true;

            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                if (payload.TryGetClaim(Claims.Iss, out var aud))
                {
                    var value = aud.GetString()!;
                    if (_policies.TryGetValue(value, out var policy))
                    {
                        return policy.TryValidateSignature(header, payload, contentBytes, signatureSegment);
                    }
                }

                return _defaultPolicy.TryValidateSignature(header, payload, contentBytes, signatureSegment);
            }
        }

        private sealed class SingleIssuerSignatureValidationPolicy : SignatureValidationPolicy
        {
            private readonly string _issuer;
            private readonly SignatureValidationPolicy _policy;

            public SingleIssuerSignatureValidationPolicy(string issuer, SignatureValidationPolicy policy)
            {
                _issuer = issuer;
                _policy = policy;
            }

            public override bool IsEnabled => true;

            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                if (payload.TryGetClaim(Claims.Iss, out var aud))
                {
                    if (aud.ValueEquals(_issuer))
                    {
                        return _policy.TryValidateSignature(header, payload, contentBytes, signatureSegment);
                    }
                }

                return SignatureValidationResult.InvalidSignature();
            }
        }

        private sealed class DefaultSignatureValidationPolicy : SignatureValidationPolicy
        {
            private readonly IKeyProvider _keyProvider;
            private readonly SignatureAlgorithm? _algorithm;

            /// <summary>
            /// Initializes a new instance of the <see cref="SignatureValidationPolicy"/> class.
            /// </summary>
            /// <param name="keyProvider"></param>
            /// <param name="algorithm"></param>
            public DefaultSignatureValidationPolicy(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
            {
                _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
                _algorithm = algorithm;
            }

            /// <inheritdoc />
            public override bool IsEnabled => true;

            /// <inheritdoc />
            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                if (signatureSegment.IsEmpty)
                {
                    return contentBytes.IsEmpty
                        ? SignatureValidationResult.Success() // This is not a JWS
                        : SignatureValidationResult.MissingSignature();
                }

                try
                {
                    int signatureBytesLength = Base64Url.GetArraySizeRequiredToDecode(signatureSegment.Length);
                    Span<byte> signatureBytes = stackalloc byte[signatureBytesLength];
                    if (Base64Url.Decode(signatureSegment, signatureBytes, out int byteConsumed, out int bytesWritten) != OperationStatus.Done)
                    {
                        return SignatureValidationResult.MalformedSignature();
                    }

                    Debug.Assert(bytesWritten == signatureBytes.Length);
                    bool keysTried = false;

                    var keySet = _keyProvider.GetKeys(header);
                    var algElement = header.Algorithm;
                    if (keySet != null)
                    {
                        var algorithm = _algorithm;
                        for (int i = 0; i < keySet.Length; i++)
                        {
                            var key = keySet[i];
                            if (key.CanUseForSignature(algElement))
                            {
                                var alg = algorithm ?? key.SignatureAlgorithm;
                                if (!(alg is null))
                                {
                                    if (key.TryGetSigner(alg, out var signer))
                                    {
                                        if (signer.Verify(contentBytes, signatureBytes))
                                        {
                                            return SignatureValidationResult.Success(key);
                                        }
                                    }
                                }

                                keysTried = true;
                            }
                        }
                    }

                    return keysTried
                        ? SignatureValidationResult.InvalidSignature()
                        : SignatureValidationResult.SignatureKeyNotFound();
                }
                catch (FormatException e)
                {
                    return SignatureValidationResult.MalformedSignature(e);
                }
            }
        }

        private sealed class NoSignatureValidationContext : SignatureValidationPolicy
        {
            /// <inheritdoc />
            public override bool IsEnabled => true;

            /// <inheritdoc />
            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return (contentBytes.Length == 0 && signatureSegment.Length == 0)
                    || (signatureSegment.IsEmpty && header.TryGetHeaderParameter(HeaderParameters.AlgUtf8, out var alg)
                        && alg.ValueEquals(SignatureAlgorithm.None.Utf8Name))
                    ? SignatureValidationResult.Success()
                    : SignatureValidationResult.InvalidSignature();
            }
        }

        private sealed class IgnoreSignatureValidationPolicy : SignatureValidationPolicy
        {
            /// <inheritdoc />
            public override bool IsEnabled => false;

            /// <inheritdoc />
            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return SignatureValidationResult.Success();
            }
        }

        private sealed class InvalidSignatureValidationPolicy : SignatureValidationPolicy
        {
            /// <inheritdoc />
            public override bool IsEnabled => false;

            /// <inheritdoc />
            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return SignatureValidationResult.InvalidSignature();
            }
        }
    }
}
