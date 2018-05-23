namespace JsonWebToken
{
    public enum TokenValidationStatus
    {
        Success,

        /// <summary>
        /// The token is not a JWT in compact representation, is not base64url encoded, and is not a JSON UTF-8 encoded.
        /// </summary>
        MalformedToken,

        /// <summary>
        ///  The 'exp' claim is missing
        /// </summary>
        MissingExpirationTime,

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
        /// The 'iss' claim is not valid.
        /// </summary>
        InvalidAudience,

        /// <summary>
        /// The 'aud' claim is missing.
        /// </summary>
        MissingAudience,

        /// <summary>
        /// The 'iss' claim is invalid.
        /// </summary>
        InvalidIssuer,

        /// <summary>
        /// The 'iss' claims is missing.
        /// </summary>
        MissingIssuer,

        /// <summary>
        /// The token was already validated previously.
        /// </summary>
        TokenReplayed,

        /// <summary>
        /// The token has expired, according to the 'nbf' claim.
        /// </summary>
        Expired,

        /// <summary>
        /// The token lifetime is incorrect, according to 'exp' and 'nbf' claims.
        /// </summary>
        InvalidLifetime,

        /// <summary>
        /// The 'enc' header parameter is missing.
        /// </summary>
        MissingEncryptionAlgorithm,

        /// <summary>
        /// The token decryption has failed.
        /// </summary>
        DecryptionFailed,

        /// <summary>
        /// The token is not yeet valid, according to the 'nbf' claim.
        /// </summary>
        NotYetValid,
        MissingContentType
    }
}