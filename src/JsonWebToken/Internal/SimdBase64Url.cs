// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using gfoidl.Base64;
using gfoidl.Base64.Internal;
using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    public sealed class SimdBase64Url : IBase64Url
    {
        private readonly Base64 _encoder = Base64.Url;

        public OperationStatus DecodeFromUtf8(ReadOnlySpan<byte> encoded, Span<byte> data, out int bytesConsumed, out int bytesWritten)
        {
            return _encoder.Decode(encoded, data, out bytesConsumed, out bytesWritten);
        }

        public OperationStatus EncodeToUtf8(ReadOnlySpan<byte> data, Span<byte> encoded, out int bytesConsumed, out int bytesWritten)
        {
            return _encoder.Encode(data, encoded, out bytesConsumed, out bytesWritten);
        }

        public int GetMaxDecodedFromUtf8Length(ReadOnlySpan<byte> encoded)
        {
            return _encoder.GetDecodedLength(encoded);
        }

        public int GetMaxDecodedFromUtf8Length(ReadOnlySpan<char> encoded)
        {
            return _encoder.GetDecodedLength(encoded);
        }

        public int GetMaxEncodedToUtf8Length(int length)
        {
            return _encoder.GetEncodedLength(length);
        }
    }
}