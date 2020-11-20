// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;

namespace JsonWebToken
{
    internal sealed class ShaNull : Sha2
    {
        public static readonly ShaNull Shared = new ShaNull();

        public override int HashSize => 0;

        public override int BlockSize => 0;

        public override void ComputeHash(ReadOnlySpan<byte> source, ReadOnlySpan<byte> prepend, Span<byte> destination, Span<byte> w)
        {
        }

        public override int GetWorkingSetSize(int sourceLength)
        {
            return 0;
        }
    }
}
