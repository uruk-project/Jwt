namespace JsonWebToken
{
    /// <summary>
    /// Contains the results of <see cref="AuthenticatedEncryptionProvider.Encrypt(byte[], byte[])"/> operation.
    /// </summary>
    public class AuthenticatedEncryptionResult
    {
        /// <summary>
        /// Initializes a new <see cref="AuthenticatedEncryptionResult"/>
        /// </summary>
        /// <param name="ciphertext">protected text.</param>
        /// <param name="iv">the initialization vector used.</param>
        /// <param name="authenticationTag">the bytes that need be passed to <see cref="AuthenticatedEncryptionProvider.Decrypt(byte[], byte[], byte[], byte[])"/>.</param>
        public AuthenticatedEncryptionResult(byte[] ciphertext, byte[] iv, byte[] authenticationTag)
        {
            Ciphertext = ciphertext;
            IV = iv;
            AuthenticationTag = authenticationTag;
        }

        /// <summary>
        /// Gets the Ciphertext.
        /// </summary>
        public byte[] Ciphertext { get; }

        /// <summary>
        /// Gets the initialization vector.
        /// </summary>
        public byte[] IV { get; }

        /// <summary>
        /// Gets the authentication tag
        /// </summary>
        public byte[] AuthenticationTag { get; }
    }
}
