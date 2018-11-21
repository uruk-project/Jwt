// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;

namespace JsonWebToken.Internal
{
    internal class AesGcm : IDisposable
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
