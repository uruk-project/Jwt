// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
        public static readonly SignatureValidationPolicy IgnoreSignature = new IgnoreSignatureValidationContext();

        /// <summary>
        /// Try to validate the token signature.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <returns></returns>
        public abstract SignatureValidationResult TryValidateSignature(JwtHeader header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment);

        /// <summary>
        /// Try to validate the token signature.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <returns></returns>
        public abstract SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment);

        /// <summary>
        /// Try to validate the token signature.
        /// </summary>
        /// <param name="header"></param>
        /// <param name="contentBytes"></param>
        /// <param name="signatureSegment"></param>
        /// <returns></returns>
        public abstract SignatureValidationResult TryValidateSignature(JwtHeaderDocument2 header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment);

        /// <summary>
        /// Creates a new <see cref="SignatureValidationPolicy"/> instance.
        /// </summary>
        /// <param name="keyProvider"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static SignatureValidationPolicy Create(IKeyProvider keyProvider, SignatureAlgorithm? algorithm)
            => new DefaultSignatureValidationPolicy(keyProvider, algorithm);

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

            public override SignatureValidationResult TryValidateSignature(JwtHeader header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                if (contentBytes.IsEmpty && signatureSegment.IsEmpty)
                {
                    // This is not a JWS
                    return SignatureValidationResult.Success();
                }

                if (signatureSegment.IsEmpty)
                {
                    return SignatureValidationResult.MissingSignature();
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
                    if (keySet != null)
                    {
                        var algorithm = _algorithm;
                        for (int i = 0; i < keySet.Length; i++)
                        {
                            var key = keySet[i];
                            if (key.CanUseForSignature(header.SignatureAlgorithm))
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

            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
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

            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument2 header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                if (contentBytes.IsEmpty && signatureSegment.IsEmpty)
                {
                    // This is not a JWS
                    return SignatureValidationResult.Success();
                }

                if (signatureSegment.IsEmpty)
                {
                    return SignatureValidationResult.MissingSignature();
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
                    if (keySet != null)
                    {
                        var algorithm = _algorithm;
                        for (int i = 0; i < keySet.Length; i++)
                        {
                            var key = keySet[i];
                            if (key.CanUseForSignature(header.SignatureAlgorithm))
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
            public override SignatureValidationResult TryValidateSignature(JwtHeader header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return (contentBytes.Length == 0 && signatureSegment.Length == 0) || (signatureSegment.IsEmpty && header.SignatureAlgorithm == SignatureAlgorithm.None)
                    ? SignatureValidationResult.Success()
                    : SignatureValidationResult.InvalidSignature();
            }

            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument2 header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return (contentBytes.Length == 0 && signatureSegment.Length == 0) || (signatureSegment.IsEmpty && header.SignatureAlgorithm == SignatureAlgorithm.None)
                    ? SignatureValidationResult.Success()
                    : SignatureValidationResult.InvalidSignature();
            }

            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return (contentBytes.Length == 0 && signatureSegment.Length == 0)
                    || (signatureSegment.IsEmpty && header.TryGetHeaderParameter(HeaderParameters.AlgUtf8, out var alg) 
                        && alg.ValueEquals(SignatureAlgorithm.None.Utf8Name))
                    ? SignatureValidationResult.Success()
                    : SignatureValidationResult.InvalidSignature();
            }
        }

        private sealed class IgnoreSignatureValidationContext : SignatureValidationPolicy
        {
            public override SignatureValidationResult TryValidateSignature(JwtHeader header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return SignatureValidationResult.Success();
            }

            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument2 header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return SignatureValidationResult.Success();
            }

            public override SignatureValidationResult TryValidateSignature(JwtHeaderDocument header, ReadOnlySpan<byte> contentBytes, ReadOnlySpan<byte> signatureSegment)
            {
                return SignatureValidationResult.Success();
            }
        }
    }
}
