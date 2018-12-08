// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

namespace JsonWebToken
{
    /// <summary>
    /// Defines the valitation status of a JWT.
    /// </summary>
    public enum TokenValidationStatus
    { 
        /// <summary>
        /// The token is valid.
        /// </summary>
        Success,

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        MalformedToken,

        /// <summary>
        /// The signature is invalid.
        /// </summary>
        InvalidSignature,

        /// <summary>
        /// The signature key is not found.
        /// </summary>
        SignatureKeyNotFound,

        /// <summary>
        /// The signature is not base64url encoded.
        /// </summary>
        MalformedSignature,

        /// <summary>
        /// The signature is not present.
        /// </summary>
        MissingSignature,

        /// <summary>
        /// The token was already validated previously.
        /// </summary>
        TokenReplayed,

        /// <summary>
        /// The token has expired, according to the 'nbf' claim.
        /// </summary>
        Expired,

        /// <summary>
        /// The 'enc' header parameter is missing.
        /// </summary>
        MissingEncryptionAlgorithm,

        /// <summary>
        /// The token decryption has failed.
        /// </summary>
        DecryptionFailed,

        /// <summary>
        /// The token is not yet valid, according to the 'nbf' claim.
        /// </summary>
        NotYetValid,

        /// <summary>
        /// The token has an invalid claim.
        /// </summary>
        InvalidClaim,

        /// <summary>
        /// The token has a missing claim.
        /// </summary>
        MissingClaim,

        /// <summary>
        /// The token has an invalid header. 
        /// </summary>
        InvalidHeader,

        /// <summary>
        /// The token has a missing header.
        /// </summary>
        MissingHeader,

        /// <summary>
        /// The token decompression has failed.
        /// </summary>
        DecompressionFailed,

        /// <summary>
        /// The encryption key was not found.
        /// </summary>
        EncryptionKeyNotFound,

        /// <summary>
        /// The 'crit' header defines a missing critical header.
        /// </summary>
        CriticalHeaderMissing,

        /// <summary>
        /// The 'crit' header defines an unsupported header.
        /// </summary>
        CriticalHeaderUnsupported
    }
}