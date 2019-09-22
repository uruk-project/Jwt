// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

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
        public static readonly SignatureValidationPolicy IgnoreSignature = new IgnoreSignatureValidationContext();

        /// <summary>
        /// Try to validate the token signature.
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <returns></returns>
        public abstract TokenValidationResult TryValidateSignature(Jwt jwt, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment);

        /// <summary>
        /// Creates a new <see cref="SignatureValidationPolicy"/> instance.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static SignatureValidationPolicy Create(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
            => new DefaultSignatureValidationPolicy(keyProvider, algorithm);

        private class DefaultSignatureValidationPolicy : SignatureValidationPolicy
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

            public override TokenValidationResult TryValidateSignature(Jwt jwt, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                if (contentBytes.IsEmpty && signatureSegment.IsEmpty)
                {
                    // This is not a JWS
                    goto Success;
                }

                if (signatureSegment.IsEmpty)
                {
                    return TokenValidationResult.MissingSignature(jwt);
                }

                try
                {
                    int signatureBytesLength = Base64Url.GetArraySizeRequiredToDecode(signatureSegment.Length);
                    Span<byte> signatureBytes = stackalloc byte[signatureBytesLength];
                    Base64Url.Decode(signatureSegment, signatureBytes, out int byteConsumed, out int bytesWritten);
                    Debug.Assert(bytesWritten == signatureBytes.Length);
                    bool keysTried = false;

                    var keySet = _keyProvider.GetKeys(jwt.Header);
                    if (keySet != null)
                    {
                        var algorithm = _algorithm;
                        for (int i = 0; i < keySet.Length; i++)
                        {
                            var key = keySet[i];
                            if (key.CanUseForSignature(jwt.Header.SignatureAlgorithm))
                            {
                                var alg = algorithm ?? key.SignatureAlgorithm;
                                if (!(alg is null))
                                {
                                    if (key.TryGetSigner(alg, out var signer))
                                    {
                                        if (signer.Verify(contentBytes, signatureBytes))
                                        {
                                            jwt.SigningKey = key;
                                            goto Success;
                                        }
                                    }
                                }

                                keysTried = true;
                            }
                        }
                    }

                    return keysTried
                        ? TokenValidationResult.InvalidSignature(jwt)
                        : TokenValidationResult.SignatureKeyNotFound(jwt);
                }
                catch (FormatException e)
                {
                    return TokenValidationResult.MalformedSignature(jwt, e);
                }

            Success:
                return TokenValidationResult.Success(jwt);
            }
        }

        private sealed class NoSignatureValidationContext : SignatureValidationPolicy
        {
            public override TokenValidationResult TryValidateSignature(Jwt jwt, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return contentBytes.Length == 0 && signatureSegment.Length == 0 || signatureSegment.IsEmpty && jwt.SignatureAlgorithm == SignatureAlgorithm.None
                    ? TokenValidationResult.Success(jwt)
                    : TokenValidationResult.InvalidSignature(jwt);
            }
        }

        private sealed class IgnoreSignatureValidationContext : SignatureValidationPolicy
        {
            public override TokenValidationResult TryValidateSignature(Jwt jwt, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return TokenValidationResult.Success(jwt);
            }
        }
    }
}
