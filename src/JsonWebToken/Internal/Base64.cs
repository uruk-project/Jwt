// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;

namespace JsonWebToken.Internal
{
    internal abstract class Base64 : IBase64
    {
        private static readonly Base64UrlEncoder _url = new Base64UrlEncoder();

        public static Base64UrlEncoder Url => _url;

        public abstract int GetEncodedLength(int length);

        public abstract OperationStatus Encode(ReadOnlySpan<byte> data, Span<byte> encoded, out int bytesConsumed, out int bytesWritten);

        public abstract int GetMaxDecodedLength(int length);

        public abstract OperationStatus Decode(ReadOnlySpan<byte> encoded, Span<byte> data, out int bytesConsumed, out int bytesWritten);
    }
}