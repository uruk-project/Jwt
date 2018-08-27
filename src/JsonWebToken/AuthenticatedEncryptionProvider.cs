using System;

namespace JsonWebToken
{
    /// <summary>
    /// Provides authenticated encryption and decryption services
    /// </summary>
    public abstract class AuthenticatedEncryptionProvider
    {
        public abstract void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> tag);

        public abstract int GetCiphertextSize(int plaintextSize);

        public abstract int GetNonceSize();

        public abstract int GetTagSize();

        public abstract bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten);
    }
}