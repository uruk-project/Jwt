using System;

namespace JsonWebToken
{
    public class AesGcmEncryptionProvider : AuthenticatedEncryptionProvider
    {
        private readonly SymmetricJwk _key;
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        public AesGcmEncryptionProvider(SymmetricJwk key, in EncryptionAlgorithm encryptionAlgorithm)
        {
            if (encryptionAlgorithm.Category != EncryptionTypes.AesGcm)
            {
                throw new ArgumentException(ErrorMessages.FormatInvariant(ErrorMessages.NotSupportedEncryptionAlgorithm, encryptionAlgorithm));
            }

            _key = key ?? throw new ArgumentNullException(nameof(key));
            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBytes << 3)
            {
                throw new ArgumentOutOfRangeException(nameof(key.KeySizeInBits), ErrorMessages.FormatInvariant(ErrorMessages.EncryptionKeyTooSmall, key.Kid, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBytes << 3, key.KeySizeInBits));
            }

            _encryptionAlgorithm = encryptionAlgorithm;
        }

        public override void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, Span<byte> tag)
        {
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
            using (var aes = new AesGcm(_key.RawK))
            {
                aes.Decrypt(nonce, ciphertext, authenticationTag, plaintext, associatedData);
                bytesWritten = plaintext.Length;
                return true;
            }
        }     
    }
}
