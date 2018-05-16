namespace JsonWebToken
{
    public enum TokenValidationStatus
    {
        Success,
        NoExpiration,
        MalformedToken,
        InvalidSignature,
        KeyNotFound,
        MalformedSignature,
        MissingSignature,
        InvalidAudience,
        MissingAudience,
        InvalidIssuer,
        MissingIssuer,
        TokenReplayed,
        Expired,
        InvalidLifetime,
        MissingEncryptionAlgorithm,
        DecryptionFailed
    }
}