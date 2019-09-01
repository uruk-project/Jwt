// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Runtime.CompilerServices;

namespace JsonWebToken
{
#if NETSTANDARD2_0 || NET461
    internal static class CryptographicOperations
    {
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void ZeroMemory(Span<byte> buffer)
        {
            // NoOptimize to prevent the optimizer from deciding this call is unnecessary
            // NoInlining to prevent the inliner from forgetting that the method was no-optimize
            buffer.Clear();
        }
    }
#endif
}