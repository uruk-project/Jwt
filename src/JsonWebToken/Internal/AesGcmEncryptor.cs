using System;

namespace JsonWebToken
{
    public sealed class AesGcmEncryptor : AuthenticatedEncryptor
    {
        private readonly SymmetricJwk _key;
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        private bool _disposed;

        public AesGcmEncryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category != EncryptionTypes.AesGcm)
            {
                Errors.ThrowNotSupportedEncryptionAlgorithm(encryptionAlgorithm);
            }

            _key = key ?? throw new ArgumentNullException(nameof(key));
            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBytes << 3)
            {
                Errors.ThrowEncryptionKeyTooSmall(key, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.KeySizeInBits);
            }

            _encryptionAlgorithm = encryptionAlgorithm;
        }

        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> tag)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            using (var aes = new AesGcm(_key.RawK))
            {
                aes.Encrypt(plaintext, nonce, ciphertext, tag, associatedData);
            }
        }

        public override int GetCiphertextSize(int plaintextSize)
        {
            return plaintextSize;
        }

        public override int GetNonceSize()
        {
            return 12;
        }

        public override int GetTagSize()
        {
            return 16;
        }

        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (_disposed)
            {
                Errors.ThrowObjectDisposed(GetType());
            }

            using (var aes = new AesGcm(_key.ToByteArray()))
            {
                aes.Decrypt(nonce, ciphertext, authenticationTag, plaintext, associatedData);
                bytesWritten = plaintext.Length;
                return true;
            }
        }

        public override void Dispose()
        {
            _disposed = true;
        }
    }
}
