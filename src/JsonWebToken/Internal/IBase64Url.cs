using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    public interface IBase64Url
    {
        int GetMaxEncodedToUtf8Length(int length);

        OperationStatus EncodeToUtf8(ReadOnlySpan<byte> data, Span<byte> encoded, out int bytesConsumed, out int bytesWritten);

        int GetMaxDecodedFromUtf8Length(int length);

        OperationStatus DecodeFromUtf8(ReadOnlySpan<byte> encoded, Span<byte> data, out int bytesConsumed, out int bytesWritten);
    }
}