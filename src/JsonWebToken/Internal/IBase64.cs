// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    internal interface IBase64
    {
        int GetEncodedLength(int length);

        OperationStatus Encode(ReadOnlySpan<byte> data, Span<byte> encoded, out int bytesConsumed, out int bytesWritten);

        int GetMaxDecodedLength(int length);

        OperationStatus Decode(ReadOnlySpan<byte> encoded, Span<byte> data, out int bytesConsumed, out int bytesWritten);
    }
}