using System;

namespace JsonWebToken
{
    public class AesGcm : IDisposable
    {
        public AesGcm(ReadOnlySpan<byte> key)
        {
        }

        public void Encrypt(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default) => throw new NotImplementedException();

        public void Decrypt(
           ReadOnlySpan<byte> nonce,
           ReadOnlySpan<byte> ciphertext,
           ReadOnlySpan<byte> tag,
           Span<byte> plaintext,
           ReadOnlySpan<byte> associatedData = default) => throw new NotImplementedException();

        public void Dispose()
        {
        }
    }
}
