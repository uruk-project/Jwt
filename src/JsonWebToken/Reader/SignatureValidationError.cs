// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>Represents the result of a signature validation.</summary>
    public class SignatureValidationError
    {
        private static readonly SignatureValidationError _invalidSignature = new SignatureValidationError(TokenValidationStatus.InvalidSignature);
        private static readonly SignatureValidationError _missingSignature = new SignatureValidationError(TokenValidationStatus.MissingSignature);
        private static readonly SignatureValidationError _signatureKeyNotFound = new SignatureValidationError(TokenValidationStatus.SignatureKeyNotFound);
        private static readonly SignatureValidationError _signatureValidationResult = new SignatureValidationError(TokenValidationStatus.MalformedSignature);
        private static readonly SignatureValidationError _missingAlgorithmResult = new SignatureValidationError(TokenValidationStatus.MissingAlgorithm);

        /// <summary>Initializes a new instance of the <see cref="SignatureValidationError"/> class.</summary>
        public SignatureValidationError(TokenValidationStatus status, Exception? exception)
        {
            Status = status;
            Exception = exception;
        }

        /// <summary>Initializes a new instance of the <see cref="SignatureValidationError"/> class.</summary>
        public SignatureValidationError(TokenValidationStatus status)
        {
            Status = status;
        }

        /// <summary>Initializes a new instance of the <see cref="SignatureValidationError"/> class.</summary>
        public SignatureValidationError(TokenValidationStatus status, Jwk signingKey)
        {
            Status = status;
            SigningKey = signingKey;
        }

        /// <summary>Gets the status of the validation.</summary>
        public TokenValidationStatus Status { get; }

        /// <summary>Gets the <see cref="Exception"/> that caused the error.</summary>
        public Exception? Exception { get; }

        /// <summary>Gets the <see cref="Jwk"/> used for the signature.</summary>
        public Jwk? SigningKey { get; }

        /// <summary>The signature is invalid.</summary>
        public static SignatureValidationError InvalidSignature()
            => _invalidSignature;

        /// <summary>The signature is not present.</summary>
        public static SignatureValidationError MissingSignature()
            => _missingSignature;

        /// <summary>The signature key is not found.</summary>
        public static SignatureValidationError SignatureKeyNotFound()
            => _signatureKeyNotFound;

        /// <summary>The signature is not base64url encoded.</summary>
        public static SignatureValidationError MalformedSignature(Exception e)
            => new SignatureValidationError(TokenValidationStatus.MalformedSignature, e);

        /// <summary>The signature is not base64url encoded.</summary>
        public static SignatureValidationError MalformedSignature()
            => _signatureValidationResult;

        /// <summary>The 'alg' header parameter is missing.</summary>
        public static SignatureValidationError MissingAlgorithm()
            => _missingAlgorithmResult;
    }
}
