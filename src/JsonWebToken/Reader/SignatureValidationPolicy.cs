// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace JsonWebToken
{
    /// <summary>
    /// Validates a token signature.
    /// </summary>
    public abstract class SignatureValidationPolicy
    {
        /// <summary>Allows to support the unsecure 'none' algorithm that require no signature.</summary>
        internal static readonly SignatureValidationPolicy NoSignature = new NoSignatureValidationPolicy();

        /// <summary>Allows to ignore the signature, whatever ther is an algorithm defined or not.</summary>
        internal static readonly SignatureValidationPolicy IgnoreSignature = new IgnoreSignatureValidationPolicy();

        internal static readonly SignatureValidationPolicy InvalidSignature = new InvalidSignatureValidationPolicy();

        /// <summary>Gets whether the signature validation is enabled.</summary>
        public abstract bool IsEnabled { get; }

        /// <summary>Try to validate the token signature.</summary>
        /// <param name="header"></param>
        /// <param name="payload"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <param name="error"></param>
        /// <returns></returns>
        public abstract bool TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment, [NotNullWhen(false)] out SignatureValidationError? error);

        /// <summary>Creates a new <see cref="SignatureValidationPolicy"/> instance.</summary>
        /// <param name="keyProvider"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        internal static SignatureValidationPolicy Create(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
        {
            return new DefaultSignatureValidationPolicy(keyProvider, algorithm);
        }

        /// <summary>Creates a new <see cref="SignatureValidationPolicy"/> instance.</summary>
        /// <param name="issuer"></param>
        /// <param name="policy"></param>
        /// <returns></returns>
        internal static SignatureValidationPolicy Create(string issuer, SignatureValidationPolicy policy)
        {
            return new SingleIssuerSignatureValidationPolicy(issuer, policy);
        }

        /// <summary>Creates a new <see cref="SignatureValidationPolicy"/> instance.</summary>
        /// <param name="policies"></param>
        /// <param name="defaultPolicy"></param>
        /// <returns></returns>
        internal static SignatureValidationPolicy Create(Dictionary<string, SignatureValidationPolicy> policies, SignatureValidationPolicy defaultPolicy)
        {
            return new MultiIssuersSignatureValidationPolicy(policies, defaultPolicy);
        }

        private sealed class MultiIssuersSignatureValidationPolicy : SignatureValidationPolicy
        {
            private readonly KeyValuePair<byte[], SignatureValidationPolicy>[] _policies;
            private readonly SignatureValidationPolicy _defaultPolicy;

            public MultiIssuersSignatureValidationPolicy(Dictionary<string, SignatureValidationPolicy> policies, SignatureValidationPolicy defaultPolicy)
            {
                _policies = policies.ToDictionary(issuer => Utf8.GetBytes(issuer.Key), v => v.Value).ToArray();
                _defaultPolicy = defaultPolicy;
            }

            public override bool IsEnabled => true;

            public override bool TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment, [NotNullWhen(false)] out SignatureValidationError? error)
            {
                if (!payload.Iss.IsEmpty)
                {
                    if (TryGetPolicy(payload.Iss, out var policy))
                    {
                        return policy.TryValidateSignature(header, payload, contentBytes, signatureSegment, out error);
                    }
                }

                return _defaultPolicy.TryValidateSignature(header, payload, contentBytes, signatureSegment, out error);
            }

            private bool TryGetPolicy(JwtElement issuer, [NotNullWhen(true)] out SignatureValidationPolicy? policy)
            {
                for (int i = 0; i < _policies.Length; i++)
                {
                    var current = _policies[i];
                    if (issuer.ValueEquals(current.Key))
                    {
                        policy = current.Value;
                        return true;
                    }
                }

                policy = null;
                return false;
            }
        }

        private sealed class SingleIssuerSignatureValidationPolicy : SignatureValidationPolicy
        {
            private readonly byte[] _issuer;
            private readonly SignatureValidationPolicy _policy;

            public SingleIssuerSignatureValidationPolicy(string issuer, SignatureValidationPolicy policy)
            {
                _issuer = Utf8.GetBytes(issuer);
                _policy = policy;
            }

            public override bool IsEnabled => true;

            public override bool TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment, [NotNullWhen(false)] out SignatureValidationError? error)
            {
                if (!payload.Iss.IsEmpty && payload.Iss.ValueEquals(_issuer))
                {
                    return _policy.TryValidateSignature(header, payload, contentBytes, signatureSegment, out error);
                }

                error = SignatureValidationError.InvalidSignature();
				return false;
            }
        }

        private sealed class DefaultSignatureValidationPolicy : SignatureValidationPolicy
        {
            private readonly IKeyProvider _keyProvider;
            private readonly SignatureAlgorithm? _algorithm;

            public DefaultSignatureValidationPolicy(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
            {
                _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
                _algorithm = algorithm;
            }

            public override bool IsEnabled => true;

            public override bool TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment, [NotNullWhen(false)] out SignatureValidationError? error)
            {
                if (signatureSegment.IsEmpty)
                {
                    if(contentBytes.IsEmpty)
					{
						// This is not a JWS
                        goto Success;
					}
					else
					{
                        error = SignatureValidationError.MissingSignature();
						goto Error;
					}
                }

                try
                {
                    int signatureBytesLength = Base64Url.GetArraySizeRequiredToDecode(signatureSegment.Length);
                    Span<byte> signatureBytes = stackalloc byte[signatureBytesLength];
                    if (Base64Url.Decode(signatureSegment, signatureBytes, out int byteConsumed, out int bytesWritten) != OperationStatus.Done)
                    {
                        error = SignatureValidationError.MalformedSignature();
						goto Error;
                    }

                    Debug.Assert(bytesWritten == signatureBytes.Length);
                    bool keysTried = false;

                    var keySet = _keyProvider.GetKeys(header);
                    var algElement = header.Alg;
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
                                    if (key.TryGetSignatureVerifier(alg, out var signatureVerifier))
                                    {
                                        if (signatureVerifier.Verify(contentBytes, signatureBytes))
                                        {
                                            error = null;
											goto Success;
                                        }
                                    }
                                }

                                keysTried = true;
                            }
                        }
                    }

                    error = keysTried
                        ? SignatureValidationError.InvalidSignature()
                        : SignatureValidationError.SignatureKeyNotFound();
                }
                catch (FormatException e)
                {
                    error = SignatureValidationError.MalformedSignature(e);
                }
				
			Error:
				return false;
				
			Success:
				error = null;
				return true;
            }
        }

        private sealed class NoSignatureValidationPolicy : SignatureValidationPolicy
        {
            public override bool IsEnabled => true;

            public override bool TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment, [NotNullWhen(false)] out SignatureValidationError? error )
            {
                if((contentBytes.Length == 0 && signatureSegment.Length == 0)
                    || (signatureSegment.IsEmpty && !header.Alg.IsEmpty && header.Alg.ValueEquals(SignatureAlgorithm.None.Utf8Name)))
				{
					error = null;
					return true;
				}

                error = SignatureValidationError.InvalidSignature();
				return false;
            }
        }

        private sealed class IgnoreSignatureValidationPolicy : SignatureValidationPolicy
        {
            public override bool IsEnabled => false;

            public override bool TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment, [NotNullWhen(false)] out SignatureValidationError? error)
            {
                error = null;
				return true;
            }
        }

        private sealed class InvalidSignatureValidationPolicy : SignatureValidationPolicy
        {
            public override bool IsEnabled => false;

            public override bool TryValidateSignature(JwtHeaderDocument header, JwtPayloadDocument payload, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment, [NotNullWhen(false)] out SignatureValidationError? error)
            {
                error = SignatureValidationError.InvalidSignature();
				return false;
            }
        }
    }
}
