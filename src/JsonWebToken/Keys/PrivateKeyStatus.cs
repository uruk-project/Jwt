namespace JsonWebToken
{
    /// <summary>
    /// Enum for the existence of private key
    /// </summary>
    public enum PrivateKeyStatus
    {
        /// <summary>
        /// private key exists for sure
        /// </summary>
        Exists,

        /// <summary>
        /// private key doesn't exist for sure
        /// </summary>
        DoesNotExist,

        /// <summary>
        /// unable to determine the existence of private key
        /// </summary>
        Unknown
    }
}
