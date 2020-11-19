// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    /// <summary>Represents the result of a signature validation.</summary>
    public class SignatureValidationResult
    {
        private static readonly SignatureValidationResult _success = new SignatureValidationResult(TokenValidationStatus.NoError);
        private static readonly SignatureValidationResult _invalidSignature = new SignatureValidationResult(TokenValidationStatus.InvalidSignature);
        private static readonly SignatureValidationResult _missingSignature = new SignatureValidationResult(TokenValidationStatus.MissingSignature);
        private static readonly SignatureValidationResult _signatureKeyNotFound = new SignatureValidationResult(TokenValidationStatus.SignatureKeyNotFound);
        private static readonly SignatureValidationResult _signatureValidationResult = new SignatureValidationResult(TokenValidationStatus.MalformedSignature);
        private static readonly SignatureValidationResult _missingAlgorithmResult = new SignatureValidationResult(TokenValidationStatus.MissingAlgorithm);

        /// <summary>Initializes a new instance of the <see cref="SignatureValidationResult"/> class.</summary>
        public SignatureValidationResult(TokenValidationStatus status, Exception? exception)
        {
            Status = status;
            Exception = exception;
        }

        /// <summary>Initializes a new instance of the <see cref="SignatureValidationResult"/> class.</summary>
        public SignatureValidationResult(TokenValidationStatus status)
        {
            Status = status;
        }

        /// <summary>Initializes a new instance of the <see cref="SignatureValidationResult"/> class.</summary>
        public SignatureValidationResult(TokenValidationStatus status, Jwk signingKey)
        {
            Status = status;
            SigningKey = signingKey;
        }

        /// <summary>Gets whether the token validation is successful.</summary>
        public bool Succedeed => Status == TokenValidationStatus.NoError;

        /// <summary>Gets the status of the validation.</summary>
        public TokenValidationStatus Status { get; }

        /// <summary>Gets the <see cref="Exception"/> that caused the error.</summary>
        public Exception? Exception { get; }

        /// <summary>Gets the <see cref="Jwk"/> used for the signature.</summary>
        public Jwk? SigningKey { get; }

        /// <summary>The signature is valid.</summary>
        public static SignatureValidationResult Success()
            => _success;

        /// <summary>The signature is valid.</summary>
        public static SignatureValidationResult Success(Jwk key)
            => new SignatureValidationResult(TokenValidationStatus.NoError, key);

        /// <summary>The signature is invalid.</summary>
        public static SignatureValidationResult InvalidSignature()
            => _invalidSignature;

        /// <summary>The signature is not present.</summary>
        public static SignatureValidationResult MissingSignature()
            => _missingSignature;

        /// <summary>The signature key is not found.</summary>
        public static SignatureValidationResult SignatureKeyNotFound()
            => _signatureKeyNotFound;

        /// <summary>The signature is not base64url encoded.</summary>
        public static SignatureValidationResult MalformedSignature(Exception e)
            => new SignatureValidationResult(TokenValidationStatus.MalformedSignature, e);

        /// <summary>The signature is not base64url encoded.</summary>
        public static SignatureValidationResult MalformedSignature()
            => _signatureValidationResult;

        /// <summary>The 'alg' header parameter is missing.</summary>
        public static SignatureValidationResult MissingAlgorithm()
            => _missingAlgorithmResult;
    }
}
