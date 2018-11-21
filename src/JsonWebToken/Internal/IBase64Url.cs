// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    internal interface IBase64Url
    {
        int GetMaxEncodedToUtf8Length(int length);

        OperationStatus EncodeToUtf8(ReadOnlySpan<byte> data, Span<byte> encoded, out int bytesConsumed, out int bytesWritten);

        int GetMaxDecodedFromUtf8Length(int length);

        OperationStatus DecodeFromUtf8(ReadOnlySpan<byte> encoded, Span<byte> data, out int bytesConsumed, out int bytesWritten);
    }
}